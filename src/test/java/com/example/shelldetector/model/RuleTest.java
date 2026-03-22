package com.example.shelldetector.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RuleTest {

    @Test
    void testRuleBuilder() {
        Rule rule = Rule.builder()
                .id("test-id")
                .name("test-rule")
                .blacklist()
                .pattern("rm\\s+-rf")
                .riskLevel(RiskLevel.DANGER)
                .description("测试规则")
                .enabled(true)
                .build();

        assertEquals("test-id", rule.getId());
        assertEquals("test-rule", rule.getName());
        assertEquals(RuleType.BLACKLIST, rule.getType());
        assertEquals("rm\\s+-rf", rule.getPattern());
        assertEquals(RiskLevel.DANGER, rule.getRiskLevel());
        assertTrue(rule.isEnabled());
    }

    @Test
    void testPatternMatching() {
        Rule rule = Rule.builder()
                .id("test-pattern")
                .pattern("rm\\s+-rf")
                .build();

        assertTrue(rule.matches("rm -rf /tmp"));
        assertFalse(rule.matches("ls -la"));
    }

    @Test
    void testDisabledRuleDoesNotMatch() {
        Rule rule = Rule.builder()
                .id("test-disabled")
                .pattern("rm\\s+-rf")
                .enabled(false)
                .build();

        assertFalse(rule.matches("rm -rf /tmp"));
    }
}
