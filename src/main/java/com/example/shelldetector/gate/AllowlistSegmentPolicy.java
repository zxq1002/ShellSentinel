package com.example.shelldetector.gate;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 只读命令白名单通道：命令名在白名单内则按其 {@link ArgPolicy} 校验参数，否则弃权。
 */
final class AllowlistSegmentPolicy implements SegmentPolicy {

    private final Set<String> allowedCommands;
    private final Map<String, ArgPolicy> argPolicies;

    AllowlistSegmentPolicy(Set<String> allowedCommands, Map<String, ArgPolicy> argPolicies) {
        this.allowedCommands = allowedCommands;
        this.argPolicies = argPolicies;
    }

    @Override
    public SegmentDecision evaluate(List<String> segment) {
        String command = segment.get(0);
        if (!allowedCommands.contains(command)) {
            return SegmentDecision.ABSTAIN;
        }
        ArgPolicy policy = argPolicies.getOrDefault(command, ArgPolicy.NO_FLAGS);
        String violation = policy.firstViolation(segment.subList(1, segment.size()));
        if (violation != null) {
            return SegmentDecision.reject(RejectReason.ARG_NOT_ALLOWED, command + " " + violation);
        }
        return SegmentDecision.ALLOW;
    }
}
