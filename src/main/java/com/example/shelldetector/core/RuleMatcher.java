package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 规则匹配器 - 提供黑白名单规则的匹配能力
 * <p>
 * 安全增强：白名单匹配时有兜底防护，防止用户自定义规则过于宽松导致绕过。
 * </p>
 */
public class RuleMatcher {

    private static final Logger logger = LoggerFactory.getLogger(RuleMatcher.class);

    /**
     * 危险分隔符 - 用于白名单兜底防护检查
     * 如果命令包含这些字符，即使匹配了白名单也要谨慎处理
     */
    private static final String DANGEROUS_DELIMITERS = ";|&<>$()`";

    /**
     * 特别危险的子 Shell 字符 - 这些字符在任何情况下都需要谨慎处理
     */
    private static final String SUBSHELL_CHARS = "$()`";

    /**
     * 匹配白名单规则
     *
     * @param command 待检测的命令
     * @param rules 规则列表
     * @return 匹配成功的白名单规则列表
     */
    public List<Rule> matchWhitelist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        if (command == null || rules == null) {
            return matched;
        }
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == RuleType.WHITELIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    /**
     * 匹配黑名单规则
     *
     * @param command 待检测的命令
     * @param rules 规则列表
     * @return 匹配成功的黑名单规则列表
     */
    public List<Rule> matchBlacklist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        if (command == null || rules == null) {
            return matched;
        }
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == RuleType.BLACKLIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    /**
     * 检查整条命令是否匹配白名单
     * <p>
     * 【安全兜底】即使规则匹配，也要检查是否包含危险分隔符，
     * 除非规则本身的 pattern 就包含这些字符（表示规则明确允许）。
     * </p>
     *
     * @param entireCommand 完整的命令字符串
     * @param rules 规则列表
     * @return true 表示整条命令匹配白名单
     */
    public boolean isEntireCommandWhitelisted(String entireCommand, List<Rule> rules) {
        if (entireCommand == null || rules == null) {
            return false;
        }
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == RuleType.WHITELIST && rule.matches(entireCommand)) {
                // 【安全兜底】检查是否包含危险分隔符，除非规则本身就允许
                // 对于子 Shell 字符，永远拒绝，除非规则明确允许（字面量包含）
                if (containsSubshellChars(entireCommand) && !rulePatternLiteralContainsSubshellChars(rule)) {
                    logger.warn("白名单规则匹配但包含子 Shell 字符，拒绝放行: {}", entireCommand);
                    return false;
                }
                // 检查其他危险分隔符
                if (containsOtherDangerousDelimiters(entireCommand) && !rulePatternContainsOtherDangerousChars(rule)) {
                    logger.warn("白名单规则匹配但包含危险分隔符，拒绝放行: {}", entireCommand);
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * 检查所有子命令是否都匹配白名单
     * <p>
     * 只有当所有子命令都匹配白名单时才返回 true。
     * </p>
     *
     * @param commands 子命令列表
     * @param rules 规则列表
     * @return true 表示所有子命令都匹配白名单
     */
    public boolean areAllCommandsWhitelisted(List<String> commands, List<Rule> rules) {
        if (commands == null || commands.isEmpty() || rules == null) {
            return false;
        }
        for (String cmd : commands) {
            if (cmd == null) {
                return false;
            }
            // 对每个子命令，不仅要匹配白名单，还要确保没有危险分隔符
            List<Rule> matched = matchWhitelist(cmd, rules);
            if (matched.isEmpty()) {
                return false;
            }
            // 【安全兜底】子命令也检查危险分隔符，除非规则本身就允许
            // 先检查子 Shell 字符
            if (containsSubshellChars(cmd) && !matched.stream().anyMatch(this::rulePatternLiteralContainsSubshellChars)) {
                logger.warn("子命令匹配白名单但包含子 Shell 字符，拒绝放行: {}", cmd);
                return false;
            }
            // 再检查其他危险分隔符
            if (containsOtherDangerousDelimiters(cmd) && !matched.stream().anyMatch(this::rulePatternContainsOtherDangerousChars)) {
                logger.warn("子命令匹配白名单但包含危险分隔符，拒绝放行: {}", cmd);
                return false;
            }
        }
        return true;
    }

    /**
     * 检查规则的 pattern 是否字面量包含子 Shell 字符（$ ` ( )）
     * 注意：不包括正则表达式中的分组括号，只检查字面量的子 Shell 字符
     *
     * @param rule 规则
     * @return true 表示规则 pattern 字面量包含子 Shell 字符
     */
    private boolean rulePatternLiteralContainsSubshellChars(Rule rule) {
        String pattern = rule.getPattern();
        if (pattern == null) {
            return false;
        }
        // 检查字面量的 $ 和 `，这是明确的子 Shell 指示符
        // ( 和 ) 在正则中太常见了（用于分组），所以只有当它们与 $ 或 ` 一起出现时才认为是子 Shell
        return pattern.contains("$") || pattern.contains("`");
    }

    /**
     * 检查规则的 pattern 是否包含其他危险字符（; | & < >）
     *
     * @param rule 规则
     * @return true 表示规则 pattern 包含危险字符
     */
    private boolean rulePatternContainsOtherDangerousChars(Rule rule) {
        String pattern = rule.getPattern();
        if (pattern == null) {
            return false;
        }
        return pattern.contains("|") || pattern.contains(";") || pattern.contains("&")
                || pattern.contains(">") || pattern.contains("<");
    }

    /**
     * 检查命令是否包含未转义的子 Shell 字符
     *
     * @param command 命令字符串
     * @return true 表示包含子 Shell 字符
     */
    private boolean containsSubshellChars(String command) {
        if (command == null) {
            return false;
        }
        return containsUnquotedChars(command, SUBSHELL_CHARS);
    }

    /**
     * 检查命令是否包含未转义的其他危险分隔符
     *
     * @param command 命令字符串
     * @return true 表示包含危险分隔符
     */
    private boolean containsOtherDangerousDelimiters(String command) {
        if (command == null) {
            return false;
        }
        return containsUnquotedChars(command, ";|&<>");
    }

    /**
     * 检查是否包含未被引号包裹的指定字符
     *
     * @param command 命令字符串
     * @param charsToCheck 要检查的字符集合
     * @return true 表示包含未被引号包裹的指定字符
     */
    private boolean containsUnquotedChars(String command, String charsToCheck) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escapeNext = false;

        for (int i = 0; i < command.length(); i++) {
            char c = command.charAt(i);

            if (escapeNext) {
                escapeNext = false;
                continue;
            }

            if (c == '\\' && !inSingleQuote) {
                escapeNext = true;
                continue;
            }

            if (c == '\'') {
                inSingleQuote = !inSingleQuote;
                continue;
            }

            if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
                continue;
            }

            // 在引号外且发现目标字符
            if (!inSingleQuote && !inDoubleQuote && charsToCheck.indexOf(c) >= 0) {
                return true;
            }
        }
        return false;
    }
}
