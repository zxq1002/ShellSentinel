package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 规则冲突检测器 - 检测黑白名单规则之间的潜在冲突
 * <p>
 * 检测场景：
 * <ul>
 *     <li>同一命令同时匹配白名单和黑名单</li>
 *     <li>多条黑名单规则之间的重叠</li>
 *     <li>多条白名单规则之间的重叠</li>
 * </ul>
 * </p>
 */
public class RuleConflictChecker {

    private static final Logger logger = LoggerFactory.getLogger(RuleConflictChecker.class);

    /**
     * 冲突检测结果
     */
    public static class Conflict {
        private final Rule rule1;
        private final Rule rule2;
        private final String description;

        public Conflict(Rule rule1, Rule rule2, String description) {
            this.rule1 = rule1;
            this.rule2 = rule2;
            this.description = description;
        }

        public Rule getRule1() { return rule1; }
        public Rule getRule2() { return rule2; }
        public String getDescription() { return description; }

        @Override
        public String toString() {
            return String.format("Conflict between '%s' (%s) and '%s' (%s): %s",
                    rule1.getName(), rule1.getId(),
                    rule2.getName(), rule2.getId(),
                    description);
        }
    }

    /**
     * 检测规则列表中的所有冲突
     *
     * @param rules 规则列表
     * @return 冲突列表，无冲突时返回空列表
     */
    public List<Conflict> checkConflicts(List<Rule> rules) {
        List<Conflict> conflicts = new ArrayList<>();

        if (rules == null || rules.size() < 2) {
            return conflicts;
        }

        // 检查所有规则对
        for (int i = 0; i < rules.size(); i++) {
            Rule rule1 = rules.get(i);
            if (rule1 == null || !rule1.isEnabled()) {
                continue;
            }

            for (int j = i + 1; j < rules.size(); j++) {
                Rule rule2 = rules.get(j);
                if (rule2 == null || !rule2.isEnabled()) {
                    continue;
                }

                Conflict conflict = checkPairConflict(rule1, rule2);
                if (conflict != null) {
                    conflicts.add(conflict);
                    logger.warn("Rule conflict detected: {}", conflict);
                }
            }
        }

        return conflicts;
    }

    /**
     * 检查两条规则之间是否存在冲突
     *
     * @param rule1 规则1
     * @param rule2 规则2
     * @return 冲突对象，无冲突时返回 null
     */
    private Conflict checkPairConflict(Rule rule1, Rule rule2) {
        // 检查是否为同一规则
        if (rule1.getId().equals(rule2.getId())) {
            return new Conflict(rule1, rule2, "Duplicate rule ID");
        }

        // 白名单 vs 黑名单 - 最关键的冲突类型
        if (rule1.getType() != rule2.getType()) {
            Rule whitelistRule = rule1.getType() == RuleType.WHITELIST ? rule1 : rule2;
            Rule blacklistRule = rule1.getType() == RuleType.BLACKLIST ? rule1 : rule2;

            if (patternsMayOverlap(whitelistRule.getPattern(), blacklistRule.getPattern())) {
                return new Conflict(whitelistRule, blacklistRule,
                        "Whitelist and blacklist patterns may overlap. " +
                                "Whitelist takes precedence, but this could cause confusion.");
            }
        }

        // 相同类型的规则重叠检测
        if (rule1.getType() == rule2.getType()) {
            if (patternsMayOverlap(rule1.getPattern(), rule2.getPattern())) {
                String type = rule1.getType() == RuleType.WHITELIST ? "Whitelist" : "Blacklist";
                return new Conflict(rule1, rule2,
                        type + " rules have overlapping patterns");
            }
        }

        return null;
    }

    /**
     * 检查两个正则表达式模式是否可能重叠匹配
     * <p>
     * 这是一个启发式检测，不保证 100% 准确，
     * 但能捕获常见的冲突情况。
     * </p>
     *
     * @param pattern1 模式1
     * @param pattern2 模式2
     * @return true 如果模式可能重叠
     */
    private boolean patternsMayOverlap(String pattern1, String pattern2) {
        if (pattern1 == null || pattern2 == null) {
            return false;
        }

        try {
            // 检查一个模式是否是另一个的子串
            if (pattern1.contains(pattern2) || pattern2.contains(pattern1)) {
                return true;
            }

            // 检查是否有明显的关键字重叠
            String p1 = simplifyPattern(pattern1);
            String p2 = simplifyPattern(pattern2);

            // 如果简化后的模式有共同的非特殊字符序列
            return hasCommonSubsequence(p1, p2);

        } catch (PatternSyntaxException e) {
            // 如果任一模式无效，不报告冲突
            logger.debug("Invalid pattern syntax during conflict check", e);
            return false;
        }
    }

    /**
     * 简化模式，移除正则特殊字符
     */
    private String simplifyPattern(String pattern) {
        return pattern.replaceAll("\\\\[wWdDsS]", "")
                .replaceAll("[.*+?^${}\\[\\]()|\\\\]", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    /**
     * 检查两个字符串是否有共同的有意义子序列
     */
    private boolean hasCommonSubsequence(String s1, String s2) {
        // 按空格分割成单词
        String[] words1 = s1.split("\\s+");
        String[] words2 = s2.split("\\s+");

        for (String w1 : words1) {
            if (w1.length() < 2) continue;
            for (String w2 : words2) {
                if (w2.length() < 2) continue;
                if (w1.equals(w2) || w1.contains(w2) || w2.contains(w1)) {
                    return true;
                }
            }
        }
        return false;
    }
}
