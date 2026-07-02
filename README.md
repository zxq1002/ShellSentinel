# ShellSentinel

面向容器云平台 exec 接口的**命令安全网关**（Java 类库）。采用 **default-deny 白名单**模型：只放行「白名单命令组成的纯管道」，并把放行结果**重建为逐参数转义的规范串**交给调用方执行。

> **定位与边界（务必先读）**
> - 本库是**安全护栏**，用于在 `sh -c` 执行前拦截写操作与任意命令执行（RCE），适配「凭证可能泄露、仅需放行只读查询」的对抗场景。
> - **不覆盖**：数据读取/外泄（纯读命令仍可读敏感数据，归 RBAC 与网络策略）、凭证安全、资源型 DoS（超大输出/长驻进程，归 exec 超时与容器 cgroup 限额）。
> - **架构红线①**：调用方必须执行网关返回的**规范串**，绝不能把原始输入串回灌给 `sh -c`。
> - **架构红线②**：规范串必须作为**独立的 argv 元素**传给 shell（如 `execve("/bin/sh", ["sh","-c", canonical])`），**绝不能**把它字符串插值进 `sh -c "<canonical>"`。否则外层 shell 会对规范串里单引号内的 `$( )`/反引号/`"` 再做一次解释 → RCE。正确：`new ProcessBuilder("/bin/sh","-c", canonical)`；错误：`sh -c "" + canonical + ""`。

## 支持的三大场景

网关对该 exec 接口的三类合法需求分别提供**独立的放行通道**，均为 default-deny、可叠加：

| # | 场景 | 放行方式 | 配置 |
|---|------|----------|------|
| ① | **只读查询验证** | 命令名白名单 + 参数策略 + 纯管道（如 `ps -ef \| grep x`） | 内置（代码固化） |
| ② | **执行镜像内可信脚本** | `sh <受信脚本路径> [args]`（精确或前缀匹配） | `gate.sh.scripts` |
| ③ | **混沌故障注入** | 整条命令白名单（精确整行 / 类型占位符模板） | `gate.exact.commands`、`gate.command.templates` |

三类通道互相独立、并列叠加，未命中任一通道一律拒绝（`COMMAND_NOT_ALLOWED`）。安全关键的命令白名单与参数策略**固化在受评审代码**中，仅部署相关的脚本前缀与混沌命令走**外部配置**（见下文「命令白名单」「受信脚本执行」「混沌注入命令」各节）。

## 背景与设计动因：为什么必须用白名单网关

### 项目背景

容器云平台对外提供 API，其中含「容器内执行命令」接口，底层通过 K8s exec 以 `sh -c "<字符串>"` 执行。需求是：在**API 鉴权凭证可能泄露**的前提下，防止攻击者借合法凭证在生产容器内执行非查询类操作（改数据 / 恶意命令执行）。

约束与场景：① 攻击者持凭证、会**主动构造绕过**（对抗性威胁）；② 合法用途仅**只读验证**（业务变更后跑命令确认是否成功），含管道如 `ps -ef | grep x`，以及执行镜像内随版本发布的可信脚本；③ 底层是 `sh -c`；④ 容器文件系统可写，无法用只读根挂载；⑤ 凭证安全本身不在本方案范围。

### 为什么黑名单行不通（结构性，而非"规则不够多"）

最初的实现是「正则黑名单 + 危险命令检测」。安全评估结论是：**黑名单作为安全边界在原理上不成立**。

- **同一危险命令有无穷等价写法**。Shell 展开语义近乎图灵完备：变量展开、命令替换 `$()`、`eval`、`$IFS`、引号拼接、`base64` 间接、反斜杠转义……实测内置 `rm -rf` 规则即可被以下平凡变形全部绕过且无任何规则兜底：

  | 绕过样本 | 为何漏过 |
  |---|---|
  | `rm -fr /` | `-fr` 不含子串 `-rf` |
  | `rm -r -f /` | 标志拆开，无连续 `-rf` |
  | `rm$IFS-rf /` | `$IFS` 替代空格 |
  | `r""m -rf /` | 引号拼接，正则按字面量匹配 |

- **危险结果可由不在黑名单上的命令达成**：`find / -delete`、`python -c '...'`、`awk 'BEGIN{system(...)}'`、`tar --checkpoint-action=exec` …… 永远列不全。
- **parser-executor 鸿沟**：你解析/匹配看到的串，与 `sh` 实际展开执行的，不是一回事。

> 结论：面对持凭证、主动绕过的攻击者，黑名单**列不全、也对不齐执行语义**。继续加规则是负收益，且制造"已防住"的虚假安全感。

### 为什么走 default-deny 白名单网关

把问题反过来：**不去枚举"什么危险"，而是只允许一个极小、可枚举、已审计的语言，其余一律拒绝（fail-closed）**。

- **只认极小语法**：白名单命令组成的纯管道（限制性识别器，见下文 EBNF）。安全性来自"只认极小语言"，而非"识别所有危险写法"。
- **闭合 parser-executor 鸿沟**：不把原始串交给 `sh`，而是解析 → 校验 → 用 token **重建逐参数转义的规范串**再执行。于是**我们控制了执行器看到的输入**——`$(...)`、`;`、`` ` ``、`$IFS` 等经单引号转义后在 shell 眼里只是字面量。该性质已用对真实 `/bin/sh` 的差分测试实证（`DifferentialShellTest`）。
- **白名单不是银弹，故再叠两层**：仅放行命令名仍不够（放进 `find`/`awk`/`sh` 等强力命令即被打穿），所以还有**参数级约束**（`ArgPolicy` 拦危险开关）和**脚本路径级约束**（受信前缀），且命令集尽量小。

一句话：**黑名单试图枚举无穷的"坏"，白名单只需固定极小的"好"——后者才可论证。**

### 为什么不引入语法解析器

完整 shell 解析器对本场景**反而更不安全**：它越想"读懂" bash，与目标 shell（容器里可能是 dash/ash/bash）的语义偏差就越多，attack surface 越大。而限制性识别器只需保守——有歧义即拒；加上重建转义已控制执行器输入，根本不需要解析保真度。详见下文「接受文法（EBNF）」。

## 设计要点

- **不把原始串交给 shell**：解析 → 校验 → 用 token 重建规范串 → 才执行。攻击者原始字节永不进入 shell。
- **限制性识别器**：只认 `简单命令 ('|' 简单命令)*` 这一微型语法，其余一律拒绝（fail-closed）。
- **三层白名单**：① 形状只允许纯管道；② 每段命令名都在白名单内（管道末段同样校验，结构性消灭 `| sh`）；③ 每段参数过该命令的参数策略。
- **逐参数转义**（安全命门）：每个参数用单引号包裹并对内部单引号做标准转义（等价 `shlex.quote`），段间只插入受控的 ` | `。

## 接受文法（EBNF）

网关只识别下面这个**极小语言**，其余一律拒绝（fail-closed）。这是安全契约，应随代码同步维护：

```ebnf
pipeline      = command , { "|" , command } ;        (* 段间仅允许管道符 *)
command       = word , { word } ;                     (* 词之间以空白分隔 *)
word          = word-piece , { word-piece } ;         (* 相邻片段拼接为一个词，如 a"b"c *)
word-piece    = bare-char | single-quoted | double-quoted ;
single-quoted = "'" , { 任意字符 - "'" } , "'" ;      (* 内部全字面量 *)
double-quoted = '"' , { 任意字符 - ( '"' | "$" | "`" | "\" ) } , '"' ;
bare-char     = 可打印字符 - 空白 - "|" - forbidden ;
forbidden     = ";" | "&" | "$" | "`" | "(" | ")" | "<" | ">"
              | "{" | "}" | "*" | "?" | "!" | "~" | "\" | "[" | "]" | "#"
              | 换行 | 回车 ;
```

附加约束（非文法可表达的部分）：

- 长度 ≤ 1024，否则 `TOO_LONG`。
- 引号未闭合 → `PARSE_FAILED`；空命令段（前导/`||`/尾随管道）→ `FORBIDDEN_SYNTAX`。
- 词的逻辑值是**去引号后**的内容；放行时每个参数都会被重新单引号转义（见 `ShellQuoter`）。
- 每段命令名须在白名单内，参数须过该命令 `ArgPolicy`。

> 设计取向：这是**限制性识别器**而非通用 shell 解析器——安全性来自「只认极小语言 + 重建转义控制执行器输入」，而非解析保真度。`FuzzPropertiesTest` 与 `DifferentialShellTest` 对此做了属性测试与对真实 `/bin/sh` 的差分验证。

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
| `ps -ef \| grep nginx` | ✅ 放行 → `'ps' '-ef' \| 'grep' 'nginx'` |
| `df -h` | ✅ 放行 → `'df' '-h'` |
| `rm -rf /` | ❌ COMMAND_NOT_ALLOWED |
| `ps -ef \| sh` | ❌ COMMAND_NOT_ALLOWED（管道末段） |
| `cat poke$(reboot)` | ❌ FORBIDDEN_SYNTAX |
| `grep x /etc/hosts > /tmp/out` | ❌ FORBIDDEN_SYNTAX（重定向） |
| `grep -f /tmp/p x` | ❌ ARG_NOT_ALLOWED（危险开关） |

## 命令白名单

默认放行以下只读命令（`CommandGate.createDefault()`）：

```
ps grep ls cat head tail wc stat df du free uptime
whoami id hostname netstat ss cut tr echo printf
```

> **有意不含 `sort`、`date`**：二者含非显而易见的危险开关——`sort --compress-program=PROG`（任意程序执行）、`sort -o`（写文件）、`date -s`（改时钟）、`date -f`（读任意文件），用开关白名单收敛到验证场景收益不足。按需可在评审后以严格开关白名单单独放回。`uniq` 同样未纳入（第二位置参数是输出文件）。

**有意不放行**：各类 shell 解释器（`sh/bash`）、`xargs/eval/exec/env`、`sudo/su`、写盘类（`tee/dd/tar`）、`find`、带命令逃逸的分页器与编辑器（`less/more/vi`）、带内嵌脚本的文本处理器（`awk/sed`）、脚本语言、网络与远程类、可写文件的下载工具等——它们不在白名单即被结构性拦截。

### 参数策略（开关白名单）

`ArgPolicy` 采用**开关白名单**：每个命令只放行**显式枚举的安全开关**，未知开关一律拒。这从根上消除了「黑名单漏列危险开关」与「GNU getopt_long 无歧义缩写绕过」两类问题——例如 `sort --compress-program`、`--out`（`--output` 缩写）、`grep --pe`（`--perl-regexp` 缩写）、`wc --files0-from`，只要不在允许集就被拒。

- 短选项逐字符校验（`-if` 拆为 `i`/`f`，都须在允许集）；长选项取 `=` 前的名字精确匹配（缩写因非精确名被拒）。
- 位置参数（通常是文件路径，属读取）默认放行；`hostname` 例外（位置参数会改主机名，限为 0）。
- 未在策略表中的命令使用 `NO_FLAGS`（fail-closed，只放行位置参数）。
- 保守取舍（只过度拒绝、不漏放）：带独立取值的开关其取值被计为位置参数；缩写需写全名。具体安全开关清单见 `CommandGate.buildDefaultArgPolicies`，可在评审后扩充。

### 受信脚本执行（可选，默认关闭）

支持执行**镜像内随版本发布的可信脚本**（等同应用代码），如 `sh /home/example/validate-db.sh`。默认网关不放行 `sh`；需显式配置受信脚本前缀后才开启：

脚本前缀**不写死在代码里**，从外部配置（properties）读入，运维可改、无需改代码：

```properties
# gate.properties（逗号分隔，可多条）
# 每条可为：精确路径（无 *，最严格）或前缀通配（恰好一个 *，* 不跨目录）
gate.sh.scripts=/home/example/validate.sh,/home/example/validate-*.sh,/opt/app/check-*.sh
```

> 路径形式：**不带通配符的完整路径**（如 `/home/example/validate.sh`）做精确匹配，最严格、推荐；**带一个 `*`** 做目录内文件名前缀匹配；含**多个 `*`** 会在加载时报错。

```java
CommandGate gate = GateConfig.fromFile("/etc/shellsentinel/gate.properties");
ExecGuard guard = new ExecGuard(gate, new Slf4jAuditSink());
```

也可用编程方式（前缀同样由调用方传入，便于来自任意配置源）：

```java
CommandGate gate = CommandGate.builder()
    .allowShScripts(loadFromAnywhere())   // Collection<String>
    .build();
```

> 设计取向：**仅脚本前缀走外部配置**；安全关键的命令白名单与参数策略仍固化在受评审代码中，避免有人借配置把 `sh`/`rm` 等放进白名单。

放行条件（全部满足）：命令为 `sh`；**首参数**是匹配受信前缀的**绝对路径**脚本（`*` 不跨 `/`、禁 `..`）；脚本之后的参数原样透传（仍逐参数转义）。因此 `sh -c '...'`、`sh /tmp/x.sh`、`echo x | sh`、路径穿越等全部被拒（`SCRIPT_NOT_ALLOWED`）。

> ⚠️ **残余风险**：路径匹配是**词法**的，只保证"文件在受信目录、文件名合规"，**不保证文件内容是镜像原版**——网关本身无法验证文件内容，须靠下面的部署 checklist 兜底。

**部署前须核对的 checklist（脚本目录信任锚点）**：

- [ ] **目录不可写**：脚本目录（如 `/home/example/`）不可被 exec 用户写入（目录归 root 或专用账户、容器以非 root 身份运行该目录不可写），否则攻击者可投放 `validate-evil.sh` 并执行——这是替代只读挂载（`readOnlyRootFilesystem` 在本方案背景下无法启用）的信任锚点。
- [ ] **拒软链**：脚本目录内的文件应为普通文件（`regular file`），防止攻击者用软链把文件名合规的路径指向目录外任意内容；`ScriptPattern` 只做词法匹配，不检查目标文件类型。
- [ ] **目录 owner 链路检查**：不仅脚本目录本身，其上层每一级目录也需确认不可被 exec 用户写入或替换（否则可通过替换父目录间接达到同等效果）。
- [ ] **PATH / 环境完整性**：网关只保证调用的是 `sh <受信脚本>`，脚本内部若再调用其它命令，其行为由脚本自身逻辑与容器 `PATH`/环境变量决定——须确保容器 `PATH` 未被污染（不含可写目录、不指向攻击者可控位置），否则脚本内部的相对调用可能被劫持。
- [ ] **配置文件本身的访问控制**：`gate.sh.scripts`/`gate.exact.commands`/`gate.command.templates` 等外部配置文件是受信配置面，须防止被非授权人员修改（配置面被攻陷等价于运维权限被攻陷，超出本网关的威胁模型）。

### 混沌注入命令（可选，默认关闭）

故障注入命令（`tc`/`stress-ng`/`kill` 等）本质危险，**不能按命令名放行**（否则攻击者得到整个工具）。因此单独提供「整条命令白名单」，只放行**预先登记的具体命令**，两种粒度：

```properties
# 精确整行：运行时规范化后逐 token 完全一致才放行（最严格）
gate.exact.commands=stress-ng --cpu 4 --timeout 60s; kill -STOP 12345

# 模板：结构钉死，仅类型占位符可变（参数需变时用）
gate.command.templates=tc qdisc add dev eth0 root netem delay {int:0..10000}ms; \
  stress-ng --cpu {int:1..16} --timeout {int:1..300}s; kill -{enum:STOP|CONT|TERM} {int}
```

- 多条以 **`;`** 分隔（`;` 在网关内本被禁，作分隔符安全）。
- 占位符：`{int}`、`{int:MIN..MAX}`（闭区间）、`{enum:A|B|C}`（固定取值之一）；其余部分必须字面量一致。
- 借精确命令前缀**拼接额外参数会被拒**（token 数不符）；越界值、结构不符、非数字均拒。
- 编程方式：`CommandGate.builder().allowExactCommands(...).allowCommandTemplates(...)`。

> 仍是 default-deny：未登记的命令一律 `COMMAND_NOT_ALLOWED`。混沌命令与只读白名单、脚本许可三者并列、互不影响。

**配置期护栏**：整行虽是精确登记，但若 `tokens[0]` 命中 `sh`/`bash`/`dash`/`ash`/`env`/`sudo`/`xargs`/`eval`/`exec`/`nohup` 等间接执行器/解释器，装配时（`ChaosPolicy.of`/`GateConfig.fromProperties`/`Builder.allowExactCommands`）会直接抛 `IllegalArgumentException`——因为这类整行虽形式合规，但等价于把该解释器的执行权限交给了配置文件。比对前会先取 `tokens[0]` 的 basename（`/bin/sh`、`./sh`、`/usr/bin/env` 等带路径写法归一化为 `sh`/`env` 再比对），防止无需任何恶意、仅是路径书写习惯就绕过该护栏。极少数确需登记此类命令的场景（如混沌演练需要 `sh <固定脚本>`），须由调用方在代码里显式调用 `Builder.allowDangerousCommand(String)` 声明例外（只豁免该字面量本身，且必须是代码变更、不能只改配置文件，确保这类例外经过评审）。

## 拒绝原因（RejectReason）

| 原因 | 含义 |
|------|------|
| `EMPTY` | 输入为空 |
| `TOO_LONG` | 超过长度上限（1024） |
| `PARSE_FAILED` | 解析失败（如引号未闭合） |
| `FORBIDDEN_SYNTAX` | 含被禁语法（分隔符、逻辑符、重定向、命令/进程替换、glob、换行等） |
| `COMMAND_NOT_ALLOWED` | 命令名不在白名单 |
| `ARG_NOT_ALLOWED` | 参数不被该命令策略允许 |
| `SCRIPT_NOT_ALLOWED` | 脚本路径缺失或不在受信前缀白名单内 |

## 审计

每次决策都会经 `AuditSink` 记录。默认 `Slf4jAuditSink`：放行记 INFO（含规范串），拒绝记 WARN（含原因与原始串），logger 名 `com.example.shelldetector.audit`。写日志前经 `AuditFormat` 净化（控制字符转义 + 长度上限）——拒绝结果的原始串正是"因含控制字符而被拒"的攻击者输入，若不净化直接落盘会被用来伪造日志行（CWE-117）。**自定义 `AuditSink` 实现同样建议复用 `AuditFormat.sanitize`（或等价处理）**，否则会重新引入同样的日志注入风险。可注入自定义实现对接 SIEM：

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
| `ScriptPattern` | 受信脚本路径前缀匹配（可选脚本执行许可） |
| `ChaosPolicy` / `CommandTemplate` | 混沌注入命令白名单（精确整行 + 类型占位符模板） |
| `GateConfig` | 从外部 properties 配置构建网关（脚本前缀、混沌命令外部化） |
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
