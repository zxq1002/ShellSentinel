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

    private CommandGate(Set<String> allowedCommands, Map<String, ArgPolicy> argPolicies) {
        this.allowedCommands = allowedCommands;
        this.argPolicies = argPolicies;
    }

    /**
     * 创建使用默认只读白名单与默认参数策略的网关。
     */
    public static CommandGate createDefault() {
        return new CommandGate(DEFAULT_ALLOWED, DEFAULT_ARG_POLICIES);
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
            if (!allowedCommands.contains(command)) {
                return GateResult.reject(RejectReason.COMMAND_NOT_ALLOWED, command);
            }
            ArgPolicy policy = argPolicies.getOrDefault(command, ArgPolicy.PERMISSIVE);
            List<String> args = seg.subList(1, seg.size());
            String violation = policy.firstViolation(args);
            if (violation != null) {
                return GateResult.reject(RejectReason.ARG_NOT_ALLOWED, command + " " + violation);
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
