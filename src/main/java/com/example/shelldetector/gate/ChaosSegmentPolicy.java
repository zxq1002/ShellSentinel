package com.example.shelldetector.gate;

import java.util.List;

/**
 * 混沌注入通道：整段命令命中预先登记的精确命令或模板则接受，否则弃权。
 * <p>
 * 该通道排在最前：混沌命令是「整条命令」级别的显式登记，比按命令名匹配的只读白名单更具体。
 * 这样运维显式登记的命令（即便其首词恰好是只读白名单命令，如 {@code tail -f ...}）能被放行，
 * 而未登记者照常落到只读通道按参数策略处理。
 * </p>
 */
final class ChaosSegmentPolicy implements SegmentPolicy {

    private final ChaosPolicy chaosPolicy;

    ChaosSegmentPolicy(ChaosPolicy chaosPolicy) {
        this.chaosPolicy = chaosPolicy;
    }

    @Override
    public SegmentDecision evaluate(List<String> segment) {
        return chaosPolicy.matches(segment) ? SegmentDecision.ALLOW : SegmentDecision.ABSTAIN;
    }
}
