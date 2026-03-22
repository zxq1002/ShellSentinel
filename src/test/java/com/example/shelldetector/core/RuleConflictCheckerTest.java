package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RuleConflictChecker 测试类
 * <p>
 * 测试规则冲突检测功能，包括：
 * - 白名单与黑名单冲突检测
 * - 相同类型规则重叠检测
 * - 重复规则ID检测
 * </p>
 */
class RuleConflictCheckerTest {

    private RuleConflictChecker checker;

    @BeforeEach
    void setUp() {
        checker = new RuleConflictChecker();
    }

    @Test
    void testEmptyRulesShouldHaveNoConflicts() {
        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(new ArrayList<>());
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testSingleRuleShouldHaveNoConflicts() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("test1")
                .pattern("rm.*")
                .blacklist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testWhitelistAndBlacklistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-ls")
                .name("ls whitelist")
                .pattern("^ls\\b")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("black-ls")
                .name("ls blacklist")
                .pattern("ls.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty());
        assertEquals(1, conflicts.size());
        assertTrue(conflicts.get(0).getDescription().contains("Whitelist and blacklist"));
    }

    @Test
    void testDuplicateIdShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("duplicate-id")
                .pattern("rm.*")
                .blacklist()
                .build());
        rules.add(Rule.builder()
                .id("duplicate-id")
                .pattern("ls.*")
                .whitelist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty());
        assertTrue(conflicts.get(0).getDescription().contains("Duplicate rule ID"));
    }

    @Test
    void testTwoBlacklistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("black1")
                .name("rm all")
                .pattern("rm.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("black2")
                .name("rm rf")
                .pattern("rm\\s+-rf")
                .blacklist()
                .riskLevel(RiskLevel.DANGER)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty());
        assertTrue(conflicts.get(0).getDescription().contains("Blacklist rules"));
    }

    @Test
    void testTwoWhitelistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white1")
                .name("list commands")
                .pattern("ls.*")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("white2")
                .name("ls la")
                .pattern("ls\\s+-la")
                .whitelist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty());
        assertTrue(conflicts.get(0).getDescription().contains("Whitelist rules"));
    }

    @Test
    void testDisabledRulesShouldBeIgnored() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-ls")
                .pattern("^ls\\b")
                .whitelist()
                .enabled(false)
                .build());
        rules.add(Rule.builder()
                .id("black-ls")
                .pattern("ls.*")
                .blacklist()
                .enabled(false)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testUnrelatedRulesShouldHaveNoConflicts() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-ls")
                .pattern("^ls\\b")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("black-rm")
                .pattern("rm.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testConflictToStringFormat() {
        Rule rule1 = Rule.builder()
                .id("rule1")
                .name("Test Rule 1")
                .pattern("test1")
                .whitelist()
                .build();
        Rule rule2 = Rule.builder()
                .id("rule2")
                .name("Test Rule 2")
                .pattern("test2")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();

        RuleConflictChecker.Conflict conflict = new RuleConflictChecker.Conflict(
                rule1, rule2, "Test conflict description");

        String str = conflict.toString();
        assertTrue(str.contains("Test Rule 1"));
        assertTrue(str.contains("Test Rule 2"));
        assertTrue(str.contains("Test conflict description"));
        assertEquals(rule1, conflict.getRule1());
        assertEquals(rule2, conflict.getRule2());
        assertEquals("Test conflict description", conflict.getDescription());
    }
}
