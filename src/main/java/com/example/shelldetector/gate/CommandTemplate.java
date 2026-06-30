package com.example.shelldetector.gate;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 混沌注入命令模板，结构钉死、仅占位符可变。
 * <p>
 * 由空白分隔的 token 组成，token 内可含占位符：
 * </p>
 * <ul>
 *     <li>{@code {int}} —— 非负整数</li>
 *     <li>{@code {int:MIN..MAX}} —— 闭区间内的非负整数</li>
 *     <li>{@code {enum:A|B|C}} —— 固定取值之一</li>
 * </ul>
 * 例：{@code tc qdisc add dev eth0 root netem delay {int:0..10000}ms}。
 * <p>
 * 匹配要求 token 数量一致且每个 token 逐一匹配；占位符之外的部分必须字面量相等。
 * </p>
 */
public final class CommandTemplate {

    private final List<TemplateToken> tokens;

    private CommandTemplate(List<TemplateToken> tokens) {
        this.tokens = tokens;
    }

    /**
     * 从模板行解析，token 以空白分隔。
     */
    public static CommandTemplate of(String line) {
        List<TemplateToken> tks = new ArrayList<>();
        for (String raw : CommandTokenizer.tokenize(line)) {
            tks.add(TemplateToken.parse(raw));
        }
        if (tks.isEmpty()) {
            throw new IllegalArgumentException("空命令模板");
        }
        return new CommandTemplate(tks);
    }

    /**
     * 判断输入 token 序列是否匹配本模板。
     *
     * @param inputTokens 命令名 + 参数（已去引号）
     */
    public boolean matches(List<String> inputTokens) {
        if (inputTokens.size() != tokens.size()) {
            return false;
        }
        for (int i = 0; i < tokens.size(); i++) {
            if (!tokens.get(i).matches(inputTokens.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 单个模板 token：编译为正则 + 整数区间校验。
     */
    private static final class TemplateToken {
        private final Pattern pattern;
        /** 每个 group 的 [min,max]，null 表示无区间约束（如纯 {int} 或 {enum}） */
        private final List<long[]> ranges;

        private TemplateToken(Pattern pattern, List<long[]> ranges) {
            this.pattern = pattern;
            this.ranges = ranges;
        }

        static TemplateToken parse(String token) {
            StringBuilder regex = new StringBuilder("^");
            List<long[]> ranges = new ArrayList<>();
            int i = 0;
            while (i < token.length()) {
                char c = token.charAt(i);
                if (c == '{') {
                    int end = token.indexOf('}', i);
                    if (end < 0) {
                        throw new IllegalArgumentException("占位符未闭合: " + token);
                    }
                    String spec = token.substring(i + 1, end);
                    if (spec.equals("int")) {
                        regex.append("([0-9]+)");
                        ranges.add(null);
                    } else if (spec.startsWith("int:")) {
                        long[] range = parseRange(spec.substring(4), token);
                        regex.append("([0-9]+)");
                        ranges.add(range);
                    } else if (spec.startsWith("enum:")) {
                        String[] vals = spec.substring(5).split("\\|");
                        regex.append('(');
                        for (int v = 0; v < vals.length; v++) {
                            if (v > 0) {
                                regex.append('|');
                            }
                            regex.append(Pattern.quote(vals[v]));
                        }
                        regex.append(')');
                        ranges.add(null);
                    } else {
                        throw new IllegalArgumentException("未知占位符: {" + spec + "}");
                    }
                    i = end + 1;
                } else {
                    int next = token.indexOf('{', i);
                    if (next < 0) {
                        next = token.length();
                    }
                    regex.append(Pattern.quote(token.substring(i, next)));
                    i = next;
                }
            }
            regex.append('$');
            return new TemplateToken(Pattern.compile(regex.toString()), ranges);
        }

        private static long[] parseRange(String spec, String token) {
            int dots = spec.indexOf("..");
            if (dots < 0) {
                throw new IllegalArgumentException("区间格式应为 MIN..MAX: " + token);
            }
            try {
                long min = Long.parseLong(spec.substring(0, dots).trim());
                long max = Long.parseLong(spec.substring(dots + 2).trim());
                return new long[]{min, max};
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("区间边界非整数: " + token, e);
            }
        }

        boolean matches(String input) {
            Matcher m = pattern.matcher(input);
            if (!m.matches()) {
                return false;
            }
            for (int g = 0; g < ranges.size(); g++) {
                long[] range = ranges.get(g);
                if (range != null) {
                    try {
                        long value = Long.parseLong(m.group(g + 1));
                        if (value < range[0] || value > range[1]) {
                            return false;
                        }
                    } catch (NumberFormatException e) {
                        return false; // 超长数字等
                    }
                }
            }
            return true;
        }
    }
}
