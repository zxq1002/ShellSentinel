package com.example.shelldetector.gate;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 混沌注入命令白名单。
 * <p>
 * 故障注入命令本质危险，不能按命令名放行；本策略只放行<b>预先登记的整条命令</b>：
 * 精确整行匹配，或带类型占位符的 {@link CommandTemplate} 模板。default-deny。
 * </p>
 * <p>
 * <b>配置期护栏</b>：整行虽是精确登记，但若 {@code tokens[0]} 命中间接执行器/解释器
 * （{@code sh}/{@code bash}/... ），实质上等价于把该解释器的执行权限交给了配置文件，
 * 与"登记具体只读/故障注入命令"的初衷相悖。因此装配时对每条登记的 {@code tokens[0]}
 * 取 basename 后做机器化黑名单校验（{@code /bin/sh}、{@code ./sh} 等带路径写法归一化
 * 为 {@code sh} 再比对，防止无需任何恶意、仅是路径书写习惯就绕过本护栏），命中即
 * fail-fast 抛异常；极少数确需登记此类命令的场景，由调用方通过
 * {@code allowDangerousExact} 显式声明例外（见
 * {@link CommandGate.Builder#allowDangerousCommand(String)}）。
 * </p>
 */
public final class ChaosPolicy {

    /** 空策略（不放行任何混沌命令） */
    public static final ChaosPolicy EMPTY = new ChaosPolicy(
            new ArrayList<List<String>>(), new ArrayList<CommandTemplate>());

    /**
     * 间接执行器/解释器黑名单：以其中之一开头的整行登记，机器可判定为高危信号，
     * 装配期一律拒绝（除非显式声明为例外）。
     */
    private static final Set<String> DANGEROUS_COMMAND_NAMES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "sh", "bash", "dash", "ash", "env", "sudo", "xargs", "eval", "exec", "nohup")));

    private final List<List<String>> exactCommands;
    private final List<CommandTemplate> templates;

    private ChaosPolicy(List<List<String>> exactCommands, List<CommandTemplate> templates) {
        this.exactCommands = exactCommands;
        this.templates = templates;
    }

    /**
     * 构造混沌策略（不放行任何危险字面量例外）。
     *
     * @param exactCommandLines 精确命令行（token 以空白分隔）
     * @param templateLines     模板行（含占位符）
     */
    public static ChaosPolicy of(List<String> exactCommandLines, List<String> templateLines) {
        return of(exactCommandLines, templateLines, Collections.<String>emptySet());
    }

    /**
     * 构造混沌策略，允许调用方显式声明一批例外整行（跳过 {@code tokens[0]} 黑名单校验）。
     *
     * @param exactCommandLines   精确命令行（token 以空白分隔）
     * @param templateLines       模板行（含占位符）
     * @param allowedDangerousExact 显式豁免黑名单校验的精确命令行（原样字符串，须与
     *                              {@code exactCommandLines} 中的条目完全一致）
     */
    public static ChaosPolicy of(List<String> exactCommandLines, List<String> templateLines,
                                  Set<String> allowedDangerousExact) {
        List<List<String>> exact = new ArrayList<>();
        for (String line : exactCommandLines) {
            List<String> tokens = CommandTokenizer.tokenize(line);
            if (!allowedDangerousExact.contains(line)) {
                rejectIfDangerous(tokens, line);
            }
            exact.add(tokens);
        }
        List<CommandTemplate> tpls = new ArrayList<>();
        for (String line : templateLines) {
            rejectIfDangerous(CommandTokenizer.tokenize(line), line);
            tpls.add(CommandTemplate.of(line));
        }
        return new ChaosPolicy(exact, tpls);
    }

    private static void rejectIfDangerous(List<String> tokens, String line) {
        if (tokens.isEmpty()) {
            return;
        }
        String token0 = tokens.get(0);
        String basename = basename(token0);
        if (DANGEROUS_COMMAND_NAMES.contains(basename)) {
            throw new IllegalArgumentException(
                    "混沌命令 tokens[0]（" + token0 + "，basename=" + basename
                            + "）命中间接执行器/解释器黑名单，"
                            + "如确需登记请改用 allowDangerousCommand 显式声明: " + line);
        }
    }

    /**
     * 取路径最后一段作为可执行文件名，用于把 {@code /bin/sh}、{@code ./sh}、
     * {@code /usr/bin/env} 等路径写法归一化为裸名字再比对黑名单——否则黑名单只做
     * 裸字符串精确匹配时，任何带路径前缀的写法（不需要任何恶意，很多人写脚本就习惯
     * 用绝对路径）都能悄悄绕过本该强制走代码评审的 {@code allowDangerousCommand} 门槛。
     */
    private static String basename(String token) {
        int slash = token.lastIndexOf('/');
        return slash < 0 ? token : token.substring(slash + 1);
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
