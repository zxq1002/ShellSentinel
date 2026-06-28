# ShellSentinel

面向容器云平台 exec 接口的**命令安全网关**（Java 类库）。采用 **default-deny 白名单**模型：只放行「白名单命令组成的纯管道」，并把放行结果**重建为逐参数转义的规范串**交给调用方执行。

> **定位与边界（务必先读）**
> - 本库是**安全护栏**，用于在 `sh -c` 执行前拦截写操作与任意命令执行（RCE），适配「凭证可能泄露、仅需放行只读查询」的对抗场景。
> - **不覆盖**：数据读取/外泄（纯读命令仍可读敏感数据，归 RBAC 与网络策略）、凭证安全、资源型 DoS（超大输出/长驻进程，归 exec 超时与容器 cgroup 限额）。
> - **架构红线**：调用方必须执行网关返回的**规范串**，绝不能把原始输入串回灌给 `sh -c`。

## 设计要点

- **不把原始串交给 shell**：解析 → 校验 → 用 token 重建规范串 → 才执行。攻击者原始字节永不进入 shell。
- **限制性识别器**：只认 `简单命令 ('|' 简单命令)*` 这一微型语法，其余一律拒绝（fail-closed）。
- **三层白名单**：① 形状只允许纯管道；② 每段命令名都在白名单内（管道末段同样校验，结构性消灭 `| sh`）；③ 每段参数过该命令的参数策略。
- **逐参数转义**（安全命门）：每个参数用单引号包裹并对内部单引号做标准转义（等价 `shlex.quote`），段间只插入受控的 ` | `。

## 快速开始

```java
import com.example.shelldetector.gate.ExecGuard;
import com.example.shelldetector.gate.CommandRejectedException;

// 应用启动时创建（默认只读白名单 + SLF4J 审计），可作单例复用
ExecGuard guard = ExecGuard.createDefault();

try {
    // 放行：返回重建后的规范串
    String canonical = guard.canonicalOrThrow(userInput);
    // 红线：执行 canonical，绝不执行 userInput
    k8sExec(pod, new String[]{"sh", "-c", canonical});
} catch (CommandRejectedException e) {
    // 拒绝：返回 4xx，原因见 e.getReason()
    log.warn("命令被拒绝: {} ({})", e.getReason(), e.getDetail());
}
```

不抛异常的用法：

```java
import com.example.shelldetector.gate.GateResult;

GateResult r = guard.inspect(userInput);
if (r.isAllowed()) {
    exec(r.getCanonicalCommand());
} else {
    reject(r.getReason());   // 见下方拒绝原因
}
```

示例：

| 输入 | 结果 |
|------|------|
| `ps -ef \| grep nginx` | ✅ 放行 → `ps '-ef' \| grep 'nginx'` |
| `df -h` | ✅ 放行 → `df '-h'` |
| `rm -rf /` | ❌ COMMAND_NOT_ALLOWED |
| `ps -ef \| sh` | ❌ COMMAND_NOT_ALLOWED（管道末段） |
| `cat poke$(reboot)` | ❌ FORBIDDEN_SYNTAX |
| `grep x /etc/hosts > /tmp/out` | ❌ FORBIDDEN_SYNTAX（重定向） |
| `grep -f /tmp/p x` | ❌ ARG_NOT_ALLOWED（危险开关） |

## 命令白名单

默认放行以下只读命令（`CommandGate.createDefault()`）：

```
ps grep ls cat head tail wc stat df du free uptime
date whoami id hostname netstat ss cut tr sort echo printf
```

> `uniq` 未纳入：其第二个位置参数是输出文件（写），无法可靠拦截；去重请用 `sort -u`。

**有意不放行**：各类 shell 解释器（`sh/bash`）、`xargs/eval/exec/env`、`sudo/su`、写盘类（`tee/dd/tar`）、`find`、带命令逃逸的分页器与编辑器（`less/more/vi`）、带内嵌脚本的文本处理器（`awk/sed`）、脚本语言、网络与远程类、可写文件的下载工具等——它们不在白名单即被结构性拦截。

### 参数策略

即便命令只读，某些开关仍危险，由 `ArgPolicy` 拦截：

| 命令 | 限制 | 原因 |
|------|------|------|
| `grep` | 禁 `-f` / `--file`、`-P` / `--perl-regexp` | 读可控模式文件；PCRE 易 ReDoS |
| `sort` | 禁 `-o` / `--output` | 写文件 |
| `date` | 禁 `-s` / `--set` | 修改系统时间 |
| `hostname` | 位置参数数 0；禁 `-F` / `--file`、`-b` / `--boot` | 任何位置参数都会修改主机名 |
| `tail` | 禁 `-f` / `-F` / `--follow` / `--retry` | 长驻进程（DoS） |

## 拒绝原因（RejectReason）

| 原因 | 含义 |
|------|------|
| `EMPTY` | 输入为空 |
| `TOO_LONG` | 超过长度上限（1024） |
| `PARSE_FAILED` | 解析失败（如引号未闭合） |
| `FORBIDDEN_SYNTAX` | 含被禁语法（分隔符、逻辑符、重定向、命令/进程替换、glob、换行等） |
| `COMMAND_NOT_ALLOWED` | 命令名不在白名单 |
| `ARG_NOT_ALLOWED` | 参数不被该命令策略允许 |

## 审计

每次决策都会经 `AuditSink` 记录。默认 `Slf4jAuditSink`：放行记 INFO（含规范串），拒绝记 WARN（含原因与原始串），logger 名 `com.example.shelldetector.audit`。可注入自定义实现对接 SIEM：

```java
ExecGuard guard = new ExecGuard(CommandGate.createDefault(), (raw, result) -> {
    // 自定义审计：写数据库 / 上报 SIEM
});
```

## 模块结构

| 类 | 职责 |
|----|------|
| `ExecGuard` | 门面：校验 + 审计 + 返回规范串 / 抛拒绝 |
| `CommandGate` | 限制性识别器 + 白名单 + 规范重建 |
| `ShellQuoter` | 逐参数单引号转义（安全命门） |
| `ArgPolicy` | 每命令危险开关拦截 |
| `GateResult` / `RejectReason` | 结果与拒绝原因模型 |
| `AuditSink` / `Slf4jAuditSink` | 审计接口与默认实现 |
| `CommandRejectedException` | 拒绝时抛出 |

## 构建

```bash
mvn clean install
```

依赖极简：仅 SLF4J（运行）+ JUnit 5（测试）。

### 架构红线守护

本库是纯校验组件，**绝不执行命令**——执行规范串是调用方的职责。`scripts/check-redline.sh` 在 CI 中校验库主代码不出现任何进程执行 API（`Runtime.exec` / `ProcessBuilder`），防止未来回归把原始串回灌给 `sh -c`：

```bash
./scripts/check-redline.sh
```

## AI 生成申明

本项目的部分代码和文档由 AI 辅助生成，建议在使用前结合项目需求进行充分的测试和代码审查。
