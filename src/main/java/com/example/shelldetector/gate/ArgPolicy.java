package com.example.shelldetector.gate;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 单个命令的参数策略（<b>开关白名单</b>模型）。
 * <p>
 * 安全姿态：只放行<b>显式枚举的安全开关</b>，未知开关一律拒绝。这从根上消除了
 * 「黑名单漏列危险开关」与「GNU getopt_long 无歧义缩写绕过」两类问题——例如
 * {@code sort --compress-program}（任意程序执行）、{@code --out}（{@code --output} 的缩写）、
 * {@code wc --files0-from}（读任意文件）等，只要不在允许集就被拒。
 * </p>
 * <p>
 * 短选项按字符逐个校验（{@code -if} 拆为 {@code i} 和 {@code f}，两者都须在允许集）；
 * 长选项取 {@code =} 之前的名字精确匹配（缩写因非精确名而被拒）。位置参数（通常是文件路径，
 * 属读取）默认放行，可用 {@code maxPositional} 限制（如 {@code hostname} 的位置参数会改主机名，限为 0）。
 * </p>
 * <p>
 * 已知保守取舍（fail-closed，只会过度拒绝、不会漏放）：① 带独立取值的开关，其取值被计为位置参数
 * （如 {@code -e -P} 中的 {@code -P} 会被当作开关校验而拒）；② 缩写一律需写全名；③ {@code --}
 * 选项终止符之后的所有 token 一律计为位置参数并受 {@code maxPositional} 约束，即便某个 token
 * 形似开关（如 {@code -i}）。这是刻意的 fail-closed 选择：若放行 {@code --} 之后形似开关的
 * token 而不计入位置参数上限，攻击者可用一个恰好在开关允许集里的字符伪装成不受控内容，
 * 绕过 {@code maxPositional=0} 这类写限制（见 {@code testDoubleDashDoesNotSwitchModeToPositional}）。
 * </p>
 */
public final class ArgPolicy {

    /** 不允许任何开关（位置参数仍放行）。命令未显式配置策略时的 fail-closed 默认。 */
    public static final ArgPolicy NO_FLAGS = new ArgPolicy(
            Collections.<Character>emptySet(), Collections.<String>emptySet(), -1);

    private final Set<Character> allowedShortFlags;
    private final Set<String> allowedLongFlags;
    private final int maxPositional;

    private ArgPolicy(Set<Character> allowedShortFlags, Set<String> allowedLongFlags, int maxPositional) {
        this.allowedShortFlags = allowedShortFlags;
        this.allowedLongFlags = allowedLongFlags;
        this.maxPositional = maxPositional;
    }

    /**
     * 构造开关白名单策略（位置参数不限）。
     *
     * @param allowedShortFlags 允许的短选项字符（如 'l'、'a'、'n'）
     * @param allowedLongFlags  允许的长选项名（不含前导 {@code --}，如 "lines"、"all"）
     */
    public static ArgPolicy allow(Set<Character> allowedShortFlags, Set<String> allowedLongFlags) {
        return new ArgPolicy(new HashSet<>(allowedShortFlags), new HashSet<>(allowedLongFlags), -1);
    }

    /**
     * 构造带位置参数上限的开关白名单策略。
     *
     * @param allowedShortFlags 允许的短选项字符
     * @param allowedLongFlags  允许的长选项名
     * @param maxPositional     位置参数上限（-1 表示不限）
     */
    public static ArgPolicy allow(Set<Character> allowedShortFlags, Set<String> allowedLongFlags, int maxPositional) {
        return new ArgPolicy(new HashSet<>(allowedShortFlags), new HashSet<>(allowedLongFlags), maxPositional);
    }

    /**
     * 校验一段命令的全部参数，返回第一个违规参数；全部合规返回 null。
     *
     * @param args 该命令的参数列表（不含命令名本身，已去引号）
     * @return 第一个违规参数；无违规返回 null
     */
    public String firstViolation(List<String> args) {
        int positional = 0;
        boolean forcePositional = false;
        for (String arg : args) {
            if (forcePositional) {
                // "--" 之后一律计为位置参数，不再按"形似开关"校验——否则形似开关但恰好
                // 在允许集里的参数（如 hostname 的 -i）会绕过 maxPositional 上限，
                // 而真正的命令行工具在 "--" 之后正是把它当位置参数处理（写操作）
                positional++;
                if (maxPositional >= 0 && positional > maxPositional) {
                    return arg;
                }
                continue;
            }
            if (arg.equals("--")) {
                forcePositional = true;
                continue;
            }
            if (arg.startsWith("--")) {
                String name = arg.substring(2);
                int eq = name.indexOf('=');
                if (eq >= 0) {
                    name = name.substring(0, eq);
                }
                if (!allowedLongFlags.contains(name)) {
                    return arg;
                }
            } else if (arg.startsWith("-") && arg.length() > 1) {
                // 短选项簇：逐字符须在允许集
                for (int i = 1; i < arg.length(); i++) {
                    if (!allowedShortFlags.contains(arg.charAt(i))) {
                        return arg;
                    }
                }
            } else {
                // 位置参数（含单独的 '-' stdin 标记）
                positional++;
                if (maxPositional >= 0 && positional > maxPositional) {
                    return arg;
                }
            }
        }
        return null;
    }
}
