package com.example.shelldetector.gate;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 单个命令的参数策略。
 * <p>
 * 即便命令本身只读，其某些用法仍具备写文件 / 改系统状态 / 长驻 / ReDoS 等能力：
 * </p>
 * <ul>
 *     <li><b>危险开关</b>：如 {@code grep -f}、{@code grep -P}、{@code sort -o}、{@code date -s}。
 *         短选项按字符逐个检查（{@code -if} 含 {@code f}）；长选项取 {@code =} 之前的名字。</li>
 *     <li><b>写经位置参数</b>：如 {@code hostname <name>} 修改主机名。通过位置参数上限拦截
 *         （{@code maxPositional}，-1 表示不限）。</li>
 * </ul>
 * <p>
 * 注意：位置参数计数对「带独立取值的开关」并不精确（如 {@code cmd -x VALUE} 中的 VALUE 会被计为
 * 位置参数）。因此 {@code maxPositional} 只用于「相关只读开关均不带独立取值」的命令（如 hostname）。
 * </p>
 */
public final class ArgPolicy {

    /** 不设任何限制的空策略 */
    public static final ArgPolicy PERMISSIVE = new ArgPolicy(
            Collections.<Character>emptySet(), Collections.<String>emptySet(), -1);

    private final Set<Character> deniedShortFlags;
    private final Set<String> deniedLongFlags;
    private final int maxPositional;

    private ArgPolicy(Set<Character> deniedShortFlags, Set<String> deniedLongFlags, int maxPositional) {
        this.deniedShortFlags = deniedShortFlags;
        this.deniedLongFlags = deniedLongFlags;
        this.maxPositional = maxPositional;
    }

    /**
     * 构造仅按开关拦截的策略（位置参数不限）。
     *
     * @param deniedShortFlags 禁用的短选项字符（如 'f'、'o'、'P'）
     * @param deniedLongFlags  禁用的长选项名（不含前导 {@code --}，如 "file"、"output"）
     */
    public static ArgPolicy deny(Set<Character> deniedShortFlags, Set<String> deniedLongFlags) {
        return new ArgPolicy(new HashSet<>(deniedShortFlags), new HashSet<>(deniedLongFlags), -1);
    }

    /**
     * 构造带位置参数上限的策略。
     *
     * @param deniedShortFlags 禁用的短选项字符
     * @param deniedLongFlags  禁用的长选项名
     * @param maxPositional    位置参数上限（-1 表示不限）
     */
    public static ArgPolicy deny(Set<Character> deniedShortFlags, Set<String> deniedLongFlags, int maxPositional) {
        return new ArgPolicy(new HashSet<>(deniedShortFlags), new HashSet<>(deniedLongFlags), maxPositional);
    }

    /**
     * 校验一段命令的全部参数，返回第一个违规参数；全部合规返回 null。
     *
     * @param args 该命令的参数列表（不含命令名本身，已去引号）
     * @return 第一个违规参数；无违规返回 null
     */
    public String firstViolation(List<String> args) {
        int positional = 0;
        for (String arg : args) {
            if (isFlag(arg)) {
                if (isFlagDenied(arg)) {
                    return arg;
                }
            } else {
                positional++;
                if (maxPositional >= 0 && positional > maxPositional) {
                    return arg;
                }
            }
        }
        return null;
    }

    private boolean isFlag(String arg) {
        return arg.startsWith("-") && arg.length() > 1;
    }

    private boolean isFlagDenied(String arg) {
        if (arg.startsWith("--")) {
            String name = arg.substring(2);
            int eq = name.indexOf('=');
            if (eq >= 0) {
                name = name.substring(0, eq);
            }
            return deniedLongFlags.contains(name);
        }
        // 短选项簇：逐字符检查
        for (int i = 1; i < arg.length(); i++) {
            if (deniedShortFlags.contains(arg.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
