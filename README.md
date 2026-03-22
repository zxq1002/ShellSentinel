# Shell 高危指令检测类库

Linux Shell 高危指令检测 Java 类库，供其他系统集成使用。

## 功能特性

- **双解析引擎** - 支持 SIMPLE（默认）和 ANTLR 两种解析器，后者支持子 Shell 递归检测
- **白名单 + 黑名单模式** - 严格的白名单优先策略
- **Fail-Safe 故障安全** - 解析失败时默认执行拦截，防止畸形绕过
- **静态规则审计** - 自动检测并提示重复 ID 或冲突的黑白名单规则
- **参数化质量验证** - 核心验收案例在双模式下 100% 对等覆盖
- Fluent Builder API 与 JSON 规则持久化

## 快速开始

```java
import com.example.shelldetector.ShellDetector;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.parser.ParserType;

// 使用默认配置和 22 条内置规则（默认 SIMPLE 解析器）
ShellDetector detector = ShellDetector.createDefault();
DetectionResult result = detector.detect("rm -rf /");

if (!result.isPassed()) {
    System.out.println("Blocked by rule: " + result.getMatchedRules().get(0).getName());
}
```

## 自定义配置

```java
ShellDetector detector = ShellDetector.builder()
    .withDefaultRules()
    .withThreshold(RiskLevel.DANGER)  // 只拦截高危
    .withParserType(ParserType.ANTLR) // 使用 ANTLR 解析器（默认 SIMPLE）
    .failOnParseError(false)          // 解析失败时拦截命令 (默认 true=抛异常)
    .failOnRuleConflict(true)         // 规则冲突时直接中断构建
    .build();
```

### 配置解析器类型

| 维度 | SIMPLE | ANTLR |
|------|--------|-------|
| **语法覆盖** | 基础分隔符、引号、转义 | 完整 Bash 语法 (递归解析) |
| **子 Shell 解析** | ❌ 仅作为字符串匹配 | ✅ 递归剥离 `$()` 并独立扫描内容 |
| **故障处理** | 状态机容错 | **Fail-Safe** (语法错误即拦截) |

也可以直接构建 `DetectionConfig` 进行细粒度配置：

```java
DetectionConfig config = DetectionConfig.builder()
    .threshold(RiskLevel.RISK)
    .parserType(ParserType.ANTLR)
    .failOnParseError(true)
    .build();

ShellDetector detector = ShellDetector.builder()
    .withConfig(config)
    .withDefaultRules()
    .build();
```

---

## 内置规则 (v1.1)

目前内置 **22** 条高危检测规则，涵盖以下领域：

### 1. 提权与审计规避 (New)
- **builtin-su-sudo**: 检测 `su`/`sudo` 权限提升。
- **builtin-history**: 检测 `history -c` 等清理历史记录、规避审计的行为。
- **builtin-crontab**: 检测对计划任务的修改（疑似持久化提权）。

### 2. 破坏性操作 (DANGER)
- **builtin-rm-rf**: 递归删除操作检测。
- **builtin-mkfs**: 格式化文件系统。
- **builtin-dd**: 块设备写操作。
- **builtin-reboot**: 系统关机/重启指令。

### 3. 网络与文件安全 (RISK)
- **builtin-reverse-shell**: 典型的反弹 Shell 模式检测。
- **builtin-chmod-chown**: 危险权限与所属权递归修改。
- **builtin-file-write**: 敏感路径重定向写操作。

### 4. 基础查询白名单 (SAFE)
- 包含 `ls`, `cat`, `echo`, `ps`, `top`, `grep`, `find`, `pwd`, `whoami` 等安全指令的受限匹配（共 7 条白名单规则）。

---

## 质量保证

项目通过了 **185** 个自动化测试案例的验证，包括：
1. **参数化对比测试**：确保同一指令在 SIMPLE 和 ANTLR 模式下的行为完全一致。
2. **安全压力测试**：验证超长输入、畸形转义、多层嵌套引号的解析稳定性。
3. **绕过攻击模拟**：模拟子 Shell 嵌套、管道符隐藏等攻击手段。

**验收结论**: 🟢 **准予交付 (Final Approved by Gemini CLI)**

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
| **1. 命令提取** | 基于 ParserType 选择解析器 | 提取基础命令及其关联的操作符（管道、重定向） |
| **2. 整条命令白名单检查** | 检查原始输入是否命中整体放行规则 | 适用于已审计的复杂脚本整串放行 |
| **3. 所有子命令白名单检查** | 确保拆分后的每一条指令都在安全白名单内 | 用于实现严格的限制性 Shell |
| **4. 所有子命令黑名单检测** | 逐一对比子命令是否命中恶意模式 | 包含对子 Shell 的递归剥离与扫描 (ANTLR) |
| **5. 风险评估** | 综合所有命中规则，按最高风险等级判定 | 风险等级 >= 阈值即拦截 |

## 规则编写建议

1. **使用精确锚点**：建议使用 `\b` 等正则锚点（例如 `\brm\b`），以防止该字符串出现在其他命令的参数中时被误拦截。
2. **处理管道符**：如果需要禁止特定操作符，可以直接在黑名单中配置如 `\|` 或 `&` 的规则。
3. **白名单最小化**：白名单模式 `(?!.*[;|&<>])` 旨在防止利用特殊字符在白名单指令后拼接恶意载荷。

## 构建项目

```bash
mvn clean install
```

---

## AI 生成申明

本项目的部分代码和文档由 AI 辅助生成，已通过严格的手工与自动化 UAT 验收，但仍建议在使用前结合项目需求进行充分的测试和代码审查。
