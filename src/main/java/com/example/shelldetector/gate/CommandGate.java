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

    /** 规范串长度上限：raw 经逐参数转义后可膨胀（单引号 1→4 字符），设界以保护下游 */
    private static final int MAX_CANONICAL_LENGTH = 2048;

    /**
     * 裸字符（引号外）中被禁止的元字符。
     * 注意：管道符 {@code |} 与空白单独处理，不在此集合；NUL 在循环顶端无条件拦截（引号内外皆拒）。
     */
    private static final String FORBIDDEN_BARE = ";&$`()<>{}*?!~\\[]#\n\r";

    /**
     * 默认只读命令白名单。
     * <p>有意不含 {@code sort}（{@code --compress-program} 任意程序执行、{@code -o} 写文件）与
     * {@code date}（{@code -s} 改时钟、{@code -f} 读任意文件）——其危险开关无法用开关白名单安全收敛到
     * 验证场景的收益，按需可在评审后以严格开关白名单单独放回。</p>
     */
    private static final Set<String> DEFAULT_ALLOWED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "ps", "grep", "ls", "cat", "head", "tail", "wc", "stat",
            "df", "du", "free", "uptime", "whoami", "id", "hostname",
            "netstat", "ss", "cut", "tr", "echo", "printf"
    )));

    /**
     * 默认参数策略：<b>每命令一份开关白名单</b>，只放行已枚举的安全开关，未知开关一律拒。
     * 未在此表的命令使用 {@link ArgPolicy#NO_FLAGS}（fail-closed，只放行位置参数）。
     */
    private static final Map<String, ArgPolicy> DEFAULT_ARG_POLICIES = buildDefaultArgPolicies();

    private static Set<Character> chars(String s) {
        Set<Character> set = new HashSet<>();
        for (int i = 0; i < s.length(); i++) {
            set.add(s.charAt(i));
        }
        return set;
    }

    private static Set<String> names(String... ns) {
        return new HashSet<>(Arrays.asList(ns));
    }

    private static Map<String, ArgPolicy> buildDefaultArgPolicies() {
        Map<String, ArgPolicy> map = new HashMap<>();
        // 进程查看（无写/执行开关）
        map.put("ps", ArgPolicy.allow(chars("aAefuxwHljyoOpCUGtLTScnrsdNm"),
                names("sort", "no-headers", "headers", "forest", "cols", "columns", "width")));
        // grep：放行常用只读开关；不含 f(读模式文件)/P(PCRE ReDoS)，缩写因非精确名被拒
        map.put("grep", ArgPolicy.allow(chars("ivcnHhlLowxEFerRsqabABCmz"),
                names("ignore-case", "invert-match", "count", "line-number", "with-filename",
                        "no-filename", "files-with-matches", "files-without-match", "only-matching",
                        "word-regexp", "line-regexp", "extended-regexp", "fixed-strings", "regexp",
                        "recursive", "include", "exclude", "exclude-dir", "color", "colour",
                        "max-count", "after-context", "before-context", "context", "quiet", "silent")));
        map.put("ls", ArgPolicy.allow(chars("aAlhtrSRdinogGcufFpQ1mxCb"),
                names("all", "almost-all", "human-readable", "sort", "reverse", "recursive",
                        "directory", "inode", "color", "classify", "group-directories-first", "time")));
        map.put("cat", ArgPolicy.allow(chars("AbenstuvET"),
                names("number", "number-nonblank", "show-all", "show-ends", "show-tabs",
                        "squeeze-blank", "show-nonprinting")));
        map.put("head", ArgPolicy.allow(chars("cnqvz"),
                names("bytes", "lines", "quiet", "silent", "verbose", "zero-terminated")));
        // tail：放行只读分页开关；不含 f/F(长驻)
        map.put("tail", ArgPolicy.allow(chars("cnqvz"),
                names("bytes", "lines", "quiet", "silent", "verbose", "zero-terminated")));
        // wc：不含 --files0-from(读任意文件)
        map.put("wc", ArgPolicy.allow(chars("cmlwL"),
                names("bytes", "chars", "lines", "words", "max-line-length")));
        map.put("stat", ArgPolicy.allow(chars("Lfct"),
                names("dereference", "file-system", "format", "printf", "terse", "cached")));
        map.put("df", ArgPolicy.allow(chars("ahHiklPTtxB"),
                names("all", "human-readable", "inodes", "local", "portability", "print-type",
                        "type", "exclude-type", "block-size", "total")));
        map.put("du", ArgPolicy.allow(chars("achHkmsxbBdLSt"),
                names("all", "human-readable", "summarize", "max-depth", "total", "bytes",
                        "block-size", "one-file-system", "threshold")));
        map.put("free", ArgPolicy.allow(chars("bkmghstwl"),
                names("bytes", "kilo", "mega", "giga", "human", "total", "wide")));
        map.put("uptime", ArgPolicy.allow(chars("psV"), names("pretty", "since")));
        map.put("whoami", ArgPolicy.allow(chars(""), names(), 0));
        map.put("id", ArgPolicy.allow(chars("agGnruzZ"),
                names("all", "group", "groups", "name", "real", "user", "zero")));
        // hostname：只放行读取类开关；不含 F(从文件设置)/b(boot)；任何位置参数会改主机名 -> 上限 0
        map.put("hostname", ArgPolicy.allow(chars("IidfsAay"),
                names("fqdn", "short", "domain", "ip-address", "all-ip-addresses", "all-fqdns",
                        "alias", "nis"), 0));
        map.put("netstat", ArgPolicy.allow(chars("atunlprsecioWxwg"),
                names("all", "tcp", "udp", "numeric", "listening", "programs", "route",
                        "statistics", "extend", "continuous", "interfaces")));
        map.put("ss", ArgPolicy.allow(chars("atunlprseiomxw46"),
                names("all", "tcp", "udp", "numeric", "listening", "processes", "resolve",
                        "summary", "extended", "info", "memory")));
        map.put("cut", ArgPolicy.allow(chars("bcdfszn"),
                names("bytes", "characters", "delimiter", "fields", "only-delimited",
                        "complement", "output-delimiter", "zero-terminated")));
        map.put("tr", ArgPolicy.allow(chars("cdstC"),
                names("complement", "delete", "squeeze-repeats", "truncate-set1")));
        map.put("echo", ArgPolicy.allow(chars("neE"), names()));
        map.put("printf", ArgPolicy.allow(chars(""), names()));
        return Collections.unmodifiableMap(map);
    }

    /**
     * 放行通道，按优先级排列。混沌通道在前：它是「整条命令」级别的显式登记，比按命令名匹配的
     * 只读白名单更具体；其后是受信脚本通道与只读白名单通道。首个非弃权裁决决定该段。
     */
    private final List<SegmentPolicy> segmentPolicies;

    private CommandGate(Set<String> allowedCommands, Map<String, ArgPolicy> argPolicies,
                        Map<String, List<ScriptPattern>> scriptRunners, ChaosPolicy chaosPolicy) {
        this.segmentPolicies = Collections.unmodifiableList(Arrays.asList(
                new ChaosSegmentPolicy(chaosPolicy),
                new ScriptRunnerSegmentPolicy(scriptRunners),
                new AllowlistSegmentPolicy(allowedCommands, argPolicies)));
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

            // NUL 无论引号内外一律拒：它会进规范串触达 exec C 字符串边界（IOException / 截断），
            // 故在引号状态分派之前先拦
            if (c == 0) {
                return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "\\u0000");
            }

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

        // 逐段经各放行通道裁决 + 重建规范串
        List<String> canonicalSegments = new ArrayList<>();
        for (List<String> seg : segments) {
            if (seg.isEmpty()) {
                return GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "empty segment");
            }

            SegmentDecision decision = SegmentDecision.ABSTAIN;
            for (SegmentPolicy policy : segmentPolicies) {
                decision = policy.evaluate(seg);
                if (decision.type() != SegmentDecision.Type.ABSTAIN) {
                    break;
                }
            }
            if (decision.type() == SegmentDecision.Type.REJECT) {
                return GateResult.reject(decision.reason(), decision.detail());
            }
            if (decision.type() == SegmentDecision.Type.ABSTAIN) {
                // 未命中任何通道
                return GateResult.reject(RejectReason.COMMAND_NOT_ALLOWED, seg.get(0));
            }

            // 命令词同样转义：确立「每个 token 都被转义」的不变量，杜绝命令词含元字符时的注入
            StringBuilder canonical = new StringBuilder(ShellQuoter.quote(seg.get(0)));
            for (int i = 1; i < seg.size(); i++) {
                canonical.append(' ').append(ShellQuoter.quote(seg.get(i)));
            }
            canonicalSegments.add(canonical.toString());
        }

        String canonical = String.join(" | ", canonicalSegments);
        if (canonical.length() > MAX_CANONICAL_LENGTH) {
            return GateResult.reject(RejectReason.TOO_LONG, "canonical length=" + canonical.length());
        }
        return GateResult.allow(canonical, segments);
    }
}
