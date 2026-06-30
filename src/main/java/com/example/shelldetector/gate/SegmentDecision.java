package com.example.shelldetector.gate;

/**
 * 单个 {@link SegmentPolicy} 对一段命令的裁决。
 * <ul>
 *     <li>{@link Type#ALLOW} —— 本策略接受该段；</li>
 *     <li>{@link Type#REJECT} —— 本策略识别了该命令但拒绝（携带原因与细节），整体校验立即拒绝；</li>
 *     <li>{@link Type#ABSTAIN} —— 与本策略无关，交由下一策略评估。</li>
 * </ul>
 */
final class SegmentDecision {

    enum Type { ALLOW, REJECT, ABSTAIN }

    static final SegmentDecision ALLOW = new SegmentDecision(Type.ALLOW, null, null);
    static final SegmentDecision ABSTAIN = new SegmentDecision(Type.ABSTAIN, null, null);

    private final Type type;
    private final RejectReason reason;
    private final String detail;

    private SegmentDecision(Type type, RejectReason reason, String detail) {
        this.type = type;
        this.reason = reason;
        this.detail = detail;
    }

    static SegmentDecision reject(RejectReason reason, String detail) {
        return new SegmentDecision(Type.REJECT, reason, detail);
    }

    Type type() {
        return type;
    }

    RejectReason reason() {
        return reason;
    }

    String detail() {
        return detail;
    }
}
