package com.example.shelldetector.gate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 命令安全网关（default-deny）。
 * <p>
 * 只放行「白名单命令组成的纯管道」，其余一律拒绝。处理流程：
 * <ol>
 *     <li>长度上限检查</li>
 *     <li>限制性识别：只认 {@code 简单命令 ('|' 简单命令)*}，出现任何被禁语法（分隔符、逻辑符、
 *         后台符、重定向、命令替换、进程替换、glob、换行等）立即拒绝</li>
 *     <li>每一段命令名都必须在白名单内（管道末段同样校验）</li>
 *     <li>放行时用 {@link ShellQuoter} 逐参数转义重建规范串，调用方执行规范串而非原始串</li>
 * </ol>
 * 解析失败或有歧义一律按拒绝处理（fail-closed）。
 * </p>
 */
public final class CommandGate {

    /** 命令串长度上限 */
    private static final int MAX_LENGTH = 1024;

    /**
     * 裸字符（引号外）中被禁止的元字符。
     * 注意：管道符 {@code |} 与空白单独处理，不在此集合。
     */
    private static final String FORBIDDEN_BARE = ";&$`()<>{}*?!~\\[]#\n\r";

    /** 默认只读命令白名单 */
    private static final Set<String> DEFAULT_ALLOWED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "ps", "grep", "ls", "cat", "head", "tail", "wc", "stat",
            "df", "du", "free", "uptime", "date", "whoami", "id", "hostname",
            "netstat", "ss", "cut", "tr", "sort", "echo", "printf"
    )));

    /** 默认参数策略：拦截白名单命令的危险开关 */
    private static final Map<String, ArgPolicy> DEFAULT_ARG_POLICIES = buildDefaultArgPolicies();

    private static Map<String, ArgPolicy> buildDefaultArgPolicies() {
        Map<String, ArgPolicy> map = new HashMap<>();
        // grep -f（读可控模式文件）、-P（PCRE，易 ReDoS）
        map.put("grep", ArgPolicy.deny(
                new HashSet<>(Arrays.asList('f', 'P')),
                new HashSet<>(Arrays.asList("file", "perl-regexp"))));
        // sort -o（写文件）
        map.put("sort", ArgPolicy.deny(
                new HashSet<>(Arrays.asList('o')),
                new HashSet<>(Arrays.asList("output"))));
        // date -s（修改系统时间）
        map.put("date", ArgPolicy.deny(
                new HashSet<>(Arrays.asList('s')),
                new HashSet<>(Arrays.asList("set"))));
        // hostname：-F/--file 从文件设置；任何位置参数都会修改主机名 -> 位置参数上限 0
        map.put("hostname", ArgPolicy.deny(
                new HashSet<>(Arrays.asList('F', 'b')),
                new HashSet<>(Arrays.asList("file", "boot")),
                0));
        // tail -f/-F（长驻，DoS）
        map.put("tail", ArgPolicy.deny(
                new HashSet<>(Arrays.asList('f', 'F')),
                new HashSet<>(Arrays.asList("follow", "retry"))));
        return Collections.unmodifiableMap(map);
    }

    private final Set<String> allowedCommands;
    private final Map<String, ArgPolicy> argPolicies;
    /** 脚本执行许可：解释器命令名 -> 受信脚本路径模式 */
    private final Map<String, List<ScriptPattern>> scriptRunners;
    /** 混沌注入命令白名单 */
    private final ChaosPolicy chaosPolicy;

    private CommandGate(Set<String> allowedCommands, Map<String, ArgPolicy> argPolicies,
                        Map<String, List<ScriptPattern>> scriptRunners, ChaosPolicy chaosPolicy) {
        this.allowedCommands = allowedCommands;
        this.argPolicies = argPolicies;
        this.scriptRunners = scriptRunners;
        this.chaosPolicy = chaosPolicy;
    }

    /**
     * 创建使用默认只读白名单与默认参数策略的网关（不开启脚本执行许可与混沌命令）。
     */
    public static CommandGate createDefault() {
        return new CommandGate(DEFAULT_ALLOWED, DEFAULT_ARG_POLICIES,
                Collections.<String, List<ScriptPattern>>emptyMap(), ChaosPolicy.EMPTY);
    }

    /**
     * 创建网关构建器（默认含只读白名单 + 默认参数策略，可追加脚本执行许可）。
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 网关构建器。
     */
    public static final class Builder {
        private final Set<String> allowed = new HashSet<>(DEFAULT_ALLOWED);
        private final Map<String, ArgPolicy> policies = new HashMap<>(DEFAULT_ARG_POLICIES);
        private final Map<String, List<ScriptPattern>> runners = new HashMap<>();
        private final List<String> exactCommands = new ArrayList<>();
        private final List<String> commandTemplates = new ArrayList<>();

        /**
         * 允许通过 {@code sh} 执行匹配给定前缀的受信脚本，如 {@code /home/example/validate-*.sh}。
         * <p>
         * 仅放行 {@code sh <匹配脚本> [args]}；sh 的所有开关（含 {@code -c}）一律禁止；
         * 脚本之后的参数原样透传（仍逐参数转义）。可多次调用追加多个模式。
         * </p>
         */
        public Builder allowShScript(String... globs) {
            return allowShScripts(Arrays.asList(globs));
        }

        /**
         * 同 {@link #allowShScript(String...)}，接受集合（便于从外部配置读入）。
         */
        public Builder allowShScripts(java.util.Collection<String> globs) {
            List<ScriptPattern> patterns = runners.computeIfAbsent("sh", k -> new ArrayList<>());
            for (String glob : globs) {
                patterns.add(ScriptPattern.of(glob));
            }
            return this;
        }

        /**
         * 允许预先登记的<b>精确整条命令</b>（用于混沌注入），如
         * {@code stress-ng --cpu 4 --timeout 60s}。运行时须规范化后逐 token 完全一致。
         */
        public Builder allowExactCommands(java.util.Collection<String> commandLines) {
            exactCommands.addAll(commandLines);
            return this;
        }

        /**
         * 允许带类型占位符的<b>命令模板</b>（用于参数可变的混沌注入），如
         * {@code tc qdisc add dev eth0 root netem delay {int:0..10000}ms}。
         */
        public Builder allowCommandTemplates(java.util.Collection<String> templateLines) {
            commandTemplates.addAll(templateLines);
            return this;
        }

        public CommandGate build() {
            return new CommandGate(
                    Collections.unmodifiableSet(allowed),
                    Collections.unmodifiableMap(policies),
                    Collections.unmodifiableMap(runners),
                    ChaosPolicy.of(exactCommands, commandTemplates));
        }
    }

    /**
     * 校验原始命令串。
     *
     * @param raw 调用方传入的原始命令字符串
     * @return 校验结果；放行时含规范串
     */
    public GateResult validate(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return GateResult.reject(RejectReason.EMPTY, null);
        }
        if (raw.length() > MAX_LENGTH) {
            return GateResult.reject(RejectReason.TOO_LONG, "length=" + raw.length());
        }

        // 限制性识别：拆分为「管道段 -> token」
        List<List<String>> segments = new ArrayList<>();
        List<String> currentSeg = new ArrayList<>();
        StringBuilder token = new StringBuilder();
        boolean tokenStarted = false;
        boolean inSingle = false;
        boolean inDouble = false;

        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);

            if (inSingle) {
                if (c == '\'') {
                    inSingle = false;
                } else {
                    token.append(c);
                }
                continue;
            }
            if (inDouble) {
                if (c == '"') {
                    inDouble = false;
                } else if (c == '$' || c == '`' || c == '\\') {
                    // 双引号内仍会展开这些字符，禁止
                    return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, String.valueOf(c));
                } else {
                    token.append(c);
                }
                continue;
            }

            // 引号外
            if (c == '\'') {
                inSingle = true;
                tokenStarted = true;
                continue;
            }
            if (c == '"') {
                inDouble = true;
                tokenStarted = true;
                continue;
            }
            if (c == ' ' || c == '\t') {
                if (tokenStarted) {
                    currentSeg.add(token.toString());
                    token.setLength(0);
                    tokenStarted = false;
                }
                continue;
            }
            if (c == '|') {
                if (tokenStarted) {
                    currentSeg.add(token.toString());
                    token.setLength(0);
                    tokenStarted = false;
                }
                if (currentSeg.isEmpty()) {
                    // 前导管道或 || ：空命令段
                    return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "|");
                }
                segments.add(currentSeg);
                currentSeg = new ArrayList<>();
                continue;
            }
            if (FORBIDDEN_BARE.indexOf(c) >= 0) {
                return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, String.valueOf(c));
            }

            token.append(c);
            tokenStarted = true;
        }

        if (inSingle || inDouble) {
            return GateResult.reject(RejectReason.PARSE_FAILED, "unterminated quote");
        }
        if (tokenStarted) {
            currentSeg.add(token.toString());
        }
        if (!currentSeg.isEmpty()) {
            segments.add(currentSeg);
        } else if (!segments.isEmpty()) {
            // 尾随管道
            return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "|");
        }

        if (segments.isEmpty()) {
            return GateResult.reject(RejectReason.EMPTY, null);
        }

        // 逐段校验命令名 + 重建规范串
        List<String> canonicalSegments = new ArrayList<>();
        for (List<String> seg : segments) {
            if (seg.isEmpty()) {
                return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "empty segment");
            }
            String command = seg.get(0);
            List<String> args = seg.subList(1, seg.size());

            if (allowedCommands.contains(command)) {
                ArgPolicy policy = argPolicies.getOrDefault(command, ArgPolicy.PERMISSIVE);
                String violation = policy.firstViolation(args);
                if (violation != null) {
                    return GateResult.reject(RejectReason.ARG_NOT_ALLOWED, command + " " + violation);
                }
            } else if (scriptRunners.containsKey(command)) {
                // 脚本执行许可：首参数必须是匹配受信前缀的脚本路径，其余参数原样透传
                if (args.isEmpty()) {
                    return GateResult.reject(RejectReason.SCRIPT_NOT_ALLOWED, command + " (missing script)");
                }
                String script = args.get(0);
                boolean matched = false;
                for (ScriptPattern pattern : scriptRunners.get(command)) {
                    if (pattern.matches(script)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    return GateResult.reject(RejectReason.SCRIPT_NOT_ALLOWED, command + " " + script);
                }
            } else if (chaosPolicy.matches(seg)) {
                // 混沌注入：整条命令命中精确登记或模板，放行
            } else {
                return GateResult.reject(RejectReason.COMMAND_NOT_ALLOWED, command);
            }

            StringBuilder canonical = new StringBuilder(command);
            for (String arg : args) {
                canonical.append(' ').append(ShellQuoter.quote(arg));
            }
            canonicalSegments.add(canonical.toString());
        }

        String canonical = String.join(" | ", canonicalSegments);
        return GateResult.allow(canonical, segments);
    }
}
