# Shell 高危指令检测类库

Linux Shell 高危指令检测 Java 类库，供其他系统集成使用。

## 功能特性

- 白名单 + 黑名单模式，白名单优先
- 基于风险等级阈值拦截
- 支持用户自定义规则的增删改
- Fluent Builder API
- JSON 规则持久化
- 管道命令和重定向操作智能检测

## 快速开始

```java
// 使用默认配置和内置规则
ShellDetector detector = ShellDetector.createDefault();
DetectionResult result = detector.detect("rm -rf /");

if (!result.isPassed()) {
    System.out.println("Blocked: " + result.getBlockReason());
}
```

## 自定义配置

```java
ShellDetector detector = ShellDetector.builder()
    .withDefaultRules()
    .withThreshold(RiskLevel.DANGER)  // 只拦截高危
    .withRulesFromJson("my-rules.json")
    .build();
```

## 动态管理规则

```java
detector.addRule(Rule.builder()
    .id("my-script")
    .name("My Dangerous Script")
    .blacklist()
    .pattern("./danger\\.sh.*")
    .riskLevel(RiskLevel.DANGER)
    .description("My custom dangerous script")
    .build());

detector.saveRulesToJson("rules.json");
```

## 风险等级

- `SAFE` - 安全
- `RISK` - 风险
- `DANGER` - 高危

## 核心检测逻辑

### 检测流程

```
┌─────────────────┐
│   输入命令       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  1. 命令提取     │
│  按 [;|&] 分割   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. 整条命令      │
│   白名单检查     │
└────────┬────────┘
         │
┌────────┴────────┐
│                 │
▼                 ▼
┌─────────┐   ┌─────────────────┐
│ 匹配成功 │   │     不匹配       │
└────┬────┘   └────────┬────────┘
     │                 │
     ▼                 ▼
┌─────────┐   ┌─────────────────┐
│  PASS   │   │ 3. 所有子命令     │
└─────────┘   │   白名单检查      │
             └────────┬────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
         ▼                         ▼
    ┌─────────┐             ┌─────────────────┐
    │ 全部匹配 │             │   存在不匹配      │
    └────┬────┘             └────────┬────────┘
         │                         │
         ▼                         ▼
    ┌─────────┐             ┌─────────────────┐
    │  PASS   │             │ 4. 所有子命令     │
    └─────────┘             │   黑名单检测      │
                            └────────┬────────┘
                                     │
                                     ▼
                           ┌─────────────────┐
                           │ 5. 风险评估      │
                           └────────┬────────┘
                                    │
                        ┌───────────┴───────────┐
                        │                       │
                        ▼                       ▼
                   ┌─────────┐           ┌─────────┐
                   │ >= 阈值  │           │  < 阈值 │
                   └────┬────┘           └────┬────┘
                        │                       │
                        ▼                       ▼
                   ┌─────────┐           ┌─────────┐
                   │  BLOCK  │           │  PASS   │
                   └─────────┘           └─────────┘
```

### 关键步骤说明

| 步骤 | 说明 | 关键细节 |
|------|------|----------|
| **1. 命令提取** | 按 `[;\|&]` 分割命令字符串 | 保留重定向操作符（`>`, `>>`, `<`, `1>`, `2>` 等）和完整上下文 |
| **2. 整条命令白名单检查** | 检查整条命令是否匹配白名单规则 | 完全根据白名单规则校验，无硬编码逻辑 |
| **3. 所有子命令白名单检查** | 检查每个子命令是否都在白名单中 | 所有子命令都匹配白名单才通过 |
| **4. 所有子命令黑名单检测** | 逐个检测子命令是否匹配黑名单规则 | 使用完整命令（包含重定向和管道符） |
| **5. 风险评估** | 确定最高风险等级并与阈值比较 | 超过阈值则拦截 |

### 设计原则

1. **白名单优先**：先检查白名单，通过则直接放行
2. **规则驱动**：所有检测逻辑都通过黑白名单规则实现，无硬编码
3. **完整上下文**：提取子命令时保留重定向信息，确保检测准确
4. **逐层过滤**：从简单到复杂，逐步缩小检测范围
5. **灵活可扩展**：通过修改规则文件即可调整检测策略

## 内置规则

### 白名单规则 (7 条)

| ID | 名称 | 模式 | 说明 |
|----|------|------|------|
| builtin-ls | ls | `^\s*ls\b(?!.*[;|&<>])` | 查看目录 |
| builtin-cat | cat | `^\s*cat\b(?!.*[;|&<>])` | 查看文件内容 |
| builtin-echo | echo/printf | `^\s*echo\b(?!.*[;|&<>])\|^\s*printf\b(?!.*[;|&<>])` | 输出文本 |
| builtin-info | info commands | `^\s*pwd\b(?!.*[;|&<>])\|^\s*whoami\b(?!.*[;|&<>])\|^\s*id\b(?!.*[;|&<>])\|^\s*date\b(?!.*[;|&<>])\|^\s*uptime\b(?!.*[;|&<>])` | 系统信息查询 |
| builtin-process-view | process view | `^\s*ps\b(?!.*[;|&<>])\|^\s*top\b(?!.*[;|&<>])` | 进程查看 |
| builtin-file-view | file view | `^\s*head\b(?!.*[;|&<>])\|^\s*tail\b(?!.*[;|&<>])\|^\s*less\b(?!.*[;|&<>])\|^\s*more\b(?!.*[;|&<>])` | 文件内容查看 |
| builtin-search | search | `^\s*grep\b(?!.*[;|&<>])\|^\s*find\b(?!.*[;|&<>])` | 搜索 |

### 黑名单规则 (12 条)

| ID | 名称 | 风险等级 | 模式 | 说明 |
|----|------|---------|------|------|
| builtin-rm-rf-root | rm -rf root | DANGER | `rm\s+.*-rf.*\s+/` | 递归删除根目录 |
| builtin-mkfs | mkfs | DANGER | `mkfs\..*` | 格式化文件系统 |
| builtin-dd | dd dangerous | DANGER | `dd.*of=/dev/` | dd写入设备 |
| builtin-reboot | reboot | DANGER | `reboot\|shutdown\|init\s+0\|init\s+6\|halt\|poweroff` | 系统重启/关机 |
| builtin-rm-rf | rm -rf | RISK | `rm\s+.*-rf` | 递归删除 |
| builtin-cp-mv | cp/mv | RISK | `cp\s+-f\|mv\s+` | 复制/移动文件 |
| builtin-touch-mkdir | touch/mkdir | RISK | `touch\s+\|mkdir\s+-p` | 创建文件/目录 |
| builtin-sed-awk-perl | sed/awk/perl in-place | RISK | `sed\s+-i\|awk\s+-i.*inplace\|perl\s+-i` | 原地修改文件 |
| builtin-chmod | chmod dangerous | RISK | `chmod\s+777\|chmod\s+-R` | 危险权限修改 |
| builtin-chown | chown/chgrp | RISK | `chown\s+-R\|chgrp\s+-R` | 递归修改所有者 |
| builtin-kill | kill -9 | RISK | `kill\s+-9\|pkill\s+-9\|killall\s+-9` | 强制终止进程 |
| builtin-file-write | file write redirection | RISK | `\s*>\s*[^\s]\|\s*1>\s*[^\s]\|\s*2>\s*[^\s]\|\s*>>\s*[^\s]` | 重定向写文件 |

## 规则编写建议

为了确保检测的准确性并减少误报，建议在编写自定义规则时遵循以下原则：

1. **使用精确锚点**：对于敏感命令（如 `rm`），建议使用 `^` 或 `\b` 等正则锚点（例如 `^rm\b`），以防止该字符串出现在其他命令的参数或 `echo` 的输出中时被误拦截。
2. **处理管道符**：由于检测引擎支持整串检测，如果需要禁止特定操作符，可以直接在黑名单中配置如 `\|` 或 `&` 的规则。
3. **白名单最小化**：白名单规则应尽可能具体，避免使用过于宽泛的匹配模式，以防恶意命令通过精心构造绕过检测。

## 手工验证

项目包含独立的手工测试程序 `ManualTest.java`，可用于命令行验证：

```bash
# 编译并运行所有测试
javac ManualTest.java && java ManualTest

# 测试单个命令
java ManualTest "ps -ef | rm -rf xxx.sh"

# 交互模式
java ManualTest interactive
```

详细使用说明请参考 [手工测试说明.md](手工测试说明.md)。

## 构建项目

```bash
mvn clean install
```

---

## AI 生成申明

本项目的部分代码和文档由 AI 辅助生成，包括但不限于：
- 部分实现逻辑
- 测试用例
- 文档内容

建议在使用前进行充分的测试和代码审查。
