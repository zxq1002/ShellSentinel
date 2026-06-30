package com.example.shelldetector.gate;

import java.util.ArrayList;
import java.util.List;

/**
 * 混沌注入命令白名单。
 * <p>
 * 故障注入命令本质危险，不能按命令名放行；本策略只放行<b>预先登记的整条命令</b>：
 * 精确整行匹配，或带类型占位符的 {@link CommandTemplate} 模板。default-deny。
 * </p>
 */
public final class ChaosPolicy {

    /** 空策略（不放行任何混沌命令） */
    public static final ChaosPolicy EMPTY = new ChaosPolicy(
            new ArrayList<List<String>>(), new ArrayList<CommandTemplate>());

    private final List<List<String>> exactCommands;
    private final List<CommandTemplate> templates;

    private ChaosPolicy(List<List<String>> exactCommands, List<CommandTemplate> templates) {
        this.exactCommands = exactCommands;
        this.templates = templates;
    }

    /**
     * 构造混沌策略。
     *
     * @param exactCommandLines 精确命令行（token 以空白分隔）
     * @param templateLines     模板行（含占位符）
     */
    public static ChaosPolicy of(List<String> exactCommandLines, List<String> templateLines) {
        List<List<String>> exact = new ArrayList<>();
        for (String line : exactCommandLines) {
            exact.add(CommandTokenizer.tokenize(line));
        }
        List<CommandTemplate> tpls = new ArrayList<>();
        for (String line : templateLines) {
            tpls.add(CommandTemplate.of(line));
        }
        return new ChaosPolicy(exact, tpls);
    }

    /**
     * 判断输入 token 序列是否命中某条精确命令或模板。
     *
     * @param inputTokens 命令名 + 参数（已去引号）
     */
    public boolean matches(List<String> inputTokens) {
        for (List<String> exact : exactCommands) {
            if (exact.equals(inputTokens)) {
                return true;
            }
        }
        for (CommandTemplate template : templates) {
            if (template.matches(inputTokens)) {
                return true;
            }
        }
        return false;
    }

}
