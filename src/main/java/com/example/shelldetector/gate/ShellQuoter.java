package com.example.shelldetector.gate;

/**
 * Shell 参数安全转义器。
 * <p>
 * 将任意字符串转义为一个 POSIX shell 字面量参数：用单引号包裹，并把内部的单引号
 * 替换为 {@code '\''}。POSIX 单引号内不进行任何展开，因此转义后的串交给 shell 时，
 * 其中的元字符（{@code $ ` ; | & < > ( )} 空格等）一律被当作普通字符，无法被重新解释。
 * </p>
 * <p>
 * 这是命令网关「重建规范串」环节的安全命门：每个参数都必须经此转义后才能拼入最终命令串。
 * </p>
 */
public final class ShellQuoter {

    private ShellQuoter() {
    }

    /**
     * 将单个参数转义为 shell 安全的字面量。
     *
     * @param arg 原始参数（不应为 null）
     * @return 单引号包裹后的安全串
     */
    public static String quote(String arg) {
        return "'" + arg.replace("'", "'\\''") + "'";
    }
}
