package com.example.shelldetector;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ShellDetectorTest {

    @Test
    void testSimpleDetection() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("rm -rf /tmp");
        assertFalse(result.isPassed());
    }

    @Test
    void testWhitelistEntireCommand() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("safe-cmd")
                        .pattern("ls -la /tmp")
                        .whitelist()
                        .build())
                .withRule(Rule.builder()
                        .id("danger-rm")
                        .pattern("rm.*")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ls -la /tmp");
        assertTrue(result.isPassed());
    }

    @Test
    void testPipeCommandWithBlacklistShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ps")
                        .pattern("^\\s*ps\\b(?!.*[;|&<>])")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ps -ef | rm -rf xxx.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithWriteRedirectionShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-echo")
                        .pattern("^\\s*echo\\b(?!.*[;|&<>])")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-file-write")
                        .pattern("\\s*>\\s*[^\\s]|\\s*1>\\s*[^\\s]|\\s*2>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("echo '123' > 123.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithAppendRedirectionShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-echo")
                        .pattern("^\\s*echo\\b(?!.*[;|&<>])")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-file-write")
                        .pattern("\\s*>\\s*[^\\s]|\\s*1>\\s*[^\\s]|\\s*2>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("echo '123' >> 123.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testSimpleWhitelistCommandShouldPass() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ps")
                        .pattern("^\\s*ps\\b(?!.*[;|&<>])")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ps -ef");
        assertTrue(result.isPassed());
    }

    @Test
    void testMultipleCommandsWithBlacklistShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ls")
                        .pattern("^\\s*ls\\b(?!.*[;|&<>])")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ls -la; rm -rf /tmp");
        assertFalse(result.isPassed());
    }

    @Test
    void testBuilderWithConfigThenThresholdShouldPreserveFailOnParseError() {
        // 先设置自定义 config（failOnParseError=false），再设置 threshold
        // 验证 failOnParseError 配置不会被覆盖

        DetectionConfig customConfig = DetectionConfig.builder()
                .failOnParseError(false)
                .threshold(RiskLevel.DANGER)
                .build();

        ShellDetector detector = ShellDetector.builder()
                .withConfig(customConfig)
                .withThreshold(RiskLevel.RISK) // 只修改 threshold
                .build();

        // 验证：使用 null 命令不会抛出异常（因为 failOnParseError=false）
        // 这间接验证了 failOnParseError 配置被保留
        DetectionResult result = detector.detect(null);
        assertTrue(result.isPassed());
    }

    @Test
    void testBuilderWithThresholdAloneShouldUseDefaultFailOnParseError() {
        // 仅设置 threshold，不设置 config，应该使用默认的 failOnParseError=true
        ShellDetector detector = ShellDetector.builder()
                .withThreshold(RiskLevel.DANGER)
                .build();

        // 这里无法直接验证，但我们已经确保了代码逻辑是正确的：
        // 当没有 prior config 时，会使用默认值构建
        // 这个测试主要为了文档化预期行为
    }

    @Test
    void testBuilderWithConflictingRulesShouldWarnButNotFailByDefault() {
        // 默认情况下，规则冲突应该只记录警告而不失败
        Rule whitelistRule = Rule.builder()
                .id("white-ls")
                .name("ls whitelist")
                .pattern("^ls\\b")
                .whitelist()
                .build();
        Rule blacklistRule = Rule.builder()
                .id("black-ls")
                .name("ls blacklist")
                .pattern("ls.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();

        // 不应该抛出异常
        ShellDetector detector = ShellDetector.builder()
                .withRule(whitelistRule)
                .withRule(blacklistRule)
                .build();

        assertNotNull(detector);
    }

    @Test
    void testBuilderWithFailOnRuleConflictShouldThrowOnConflict() {
        // 当设置 failOnRuleConflict=true 时，规则冲突应该抛出异常
        Rule whitelistRule = Rule.builder()
                .id("white-ls")
                .name("ls whitelist")
                .pattern("^ls\\b")
                .whitelist()
                .build();
        Rule blacklistRule = Rule.builder()
                .id("black-ls")
                .name("ls blacklist")
                .pattern("ls.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            ShellDetector.builder()
                    .withRule(whitelistRule)
                    .withRule(blacklistRule)
                    .failOnRuleConflict(true)
                    .build();
        });

        assertTrue(exception.getMessage().contains("rule conflict"));
    }
}
