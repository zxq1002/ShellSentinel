package com.example.shelldetector.gate;

import java.util.List;
import java.util.Map;

/**
 * 受信脚本通道：命令名是已配置的解释器（如 {@code sh}）时，要求首参数为匹配受信前缀的脚本路径；
 * 否则弃权。sh 的所有开关因首参数须为脚本路径而被自然拒绝（堵死 {@code sh -c}）。
 */
final class ScriptRunnerSegmentPolicy implements SegmentPolicy {

    private final Map<String, List<ScriptPattern>> scriptRunners;

    ScriptRunnerSegmentPolicy(Map<String, List<ScriptPattern>> scriptRunners) {
        this.scriptRunners = scriptRunners;
    }

    @Override
    public SegmentDecision evaluate(List<String> segment) {
        String command = segment.get(0);
        List<ScriptPattern> patterns = scriptRunners.get(command);
        if (patterns == null) {
            return SegmentDecision.ABSTAIN;
        }
        List<String> args = segment.subList(1, segment.size());
        if (args.isEmpty()) {
            return SegmentDecision.reject(RejectReason.SCRIPT_NOT_ALLOWED, command + " (missing script)");
        }
        String script = args.get(0);
        for (ScriptPattern pattern : patterns) {
            if (pattern.matches(script)) {
                return SegmentDecision.ALLOW;
            }
        }
        return SegmentDecision.reject(RejectReason.SCRIPT_NOT_ALLOWED, command + " " + script);
    }
}
