package com.example.shelldetector.gate;

/**
 * 审计日志展示层净化（CWE-117 日志注入兜底）。
 * <p>
 * {@link CommandGate} 已在解析阶段无条件拒绝 {@code \n \r \v \f} 等控制字符（见
 * {@code CommandGate.isAlwaysForbiddenControl}），但 REJECT 结果里的 rawCommand 正是
 * 「因含这些字符而被拒」的原始输入——它仍会被审计 sink 记录一次。本类在写日志前对显示文本
 * 做 C0/DEL 控制字符转义，并加展示长度上限，防止攻击者用超长或含控制字符的原始串伪造/撑爆
 * 日志行。<b>只用于日志展示</b>，不影响 {@link GateResult} 里用于实际执行的规范串。
 * </p>
 */
final class AuditFormat {

    private static final int MAX_DISPLAY_LENGTH = 256;

    private AuditFormat() {
    }

    static String sanitize(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                sb.append(String.format("\\x%02x", (int) c));
            } else {
                sb.append(c);
            }
        }
        if (sb.length() > MAX_DISPLAY_LENGTH) {
            sb.setLength(MAX_DISPLAY_LENGTH);
            sb.append("...(truncated)");
        }
        return sb.toString();
    }
}
