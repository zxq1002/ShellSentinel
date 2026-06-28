package com.example.shelldetector.gate;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * 单个命令的参数策略。
 * <p>
 * 即便命令本身只读，其某些开关仍具备写文件 / 子进程执行 / ReDoS 等能力（如
 * {@code grep -f}、{@code grep -P}、{@code sort -o}）。本策略以禁用名单的形式拦截这些开关。
 * </p>
 * <p>
 * 短选项按字符逐个检查：{@code -if} 会被识别为同时含 {@code i} 和 {@code f}；
 * 长选项取 {@code =} 之前的名字检查：{@code --output=/x} 视为 {@code output}。
 * </p>
 */
public final class ArgPolicy {

    /** 不设任何限制的空策略 */
    public static final ArgPolicy PERMISSIVE = new ArgPolicy(
            Collections.<Character>emptySet(), Collections.<String>emptySet());

    private final Set<Character> deniedShortFlags;
    private final Set<String> deniedLongFlags;

    private ArgPolicy(Set<Character> deniedShortFlags, Set<String> deniedLongFlags) {
        this.deniedShortFlags = deniedShortFlags;
        this.deniedLongFlags = deniedLongFlags;
    }

    /**
     * 构造参数策略。
     *
     * @param deniedShortFlags 禁用的短选项字符（如 'f'、'o'、'P'）
     * @param deniedLongFlags  禁用的长选项名（不含前导 {@code --}，如 "file"、"output"）
     */
    public static ArgPolicy deny(Set<Character> deniedShortFlags, Set<String> deniedLongFlags) {
        return new ArgPolicy(new HashSet<>(deniedShortFlags), new HashSet<>(deniedLongFlags));
    }

    /**
     * 判断单个参数是否被允许。
     *
     * @param arg 参数（已去除引号的逻辑值）
     * @return true 表示允许
     */
    public boolean isAllowed(String arg) {
        if (arg.startsWith("--")) {
            String name = arg.substring(2);
            int eq = name.indexOf('=');
            if (eq >= 0) {
                name = name.substring(0, eq);
            }
            return !deniedLongFlags.contains(name);
        }
        if (arg.startsWith("-") && arg.length() > 1) {
            for (int i = 1; i < arg.length(); i++) {
                if (deniedShortFlags.contains(arg.charAt(i))) {
                    return false;
                }
            }
            return true;
        }
        // 位置参数，无开关限制
        return true;
    }
}
