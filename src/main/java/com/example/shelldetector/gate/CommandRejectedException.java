package com.example.shelldetector.gate;

/**
 * 命令被网关拒绝时抛出。
 */
public class CommandRejectedException extends Exception {

    private final RejectReason reason;
    private final String detail;

    public CommandRejectedException(RejectReason reason, String detail) {
        super("Command rejected: " + reason + (detail != null ? " (" + detail + ")" : ""));
        this.reason = reason;
        this.detail = detail;
    }

    /** 拒绝原因 */
    public RejectReason getReason() {
        return reason;
    }

    /** 拒绝细节，可能为 null */
    public String getDetail() {
        return detail;
    }
}
