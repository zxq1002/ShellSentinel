package com.example.shelldetector.gate;

import java.util.Collections;
import java.util.List;

/**
 * 命令网关校验结果。
 * <p>
 * 放行时携带重建后的规范串（{@link #getCanonicalCommand()}），调用方应执行此规范串而非原始串；
 * 拒绝时携带拒绝原因与细节。
 * </p>
 */
public final class GateResult {

    private final boolean allowed;
    private final String canonicalCommand;
    private final RejectReason reason;
    private final String detail;
    private final List<List<String>> stages;

    private GateResult(boolean allowed, String canonicalCommand, RejectReason reason,
                       String detail, List<List<String>> stages) {
        this.allowed = allowed;
        this.canonicalCommand = canonicalCommand;
        this.reason = reason;
        this.detail = detail;
        this.stages = stages;
    }

    /**
     * 构造放行结果。
     *
     * @param canonicalCommand 重建后的规范命令串（应执行此串）
     * @param stages           管道各段（命令名 + 参数），用于审计
     */
    static GateResult allow(String canonicalCommand, List<List<String>> stages) {
        return new GateResult(true, canonicalCommand, null, null, stages);
    }

    /**
     * 构造拒绝结果。
     *
     * @param reason 拒绝原因
     * @param detail 细节（如命中的命令名 / 字符），可为 null
     */
    static GateResult reject(RejectReason reason, String detail) {
        return new GateResult(false, null, reason, detail, Collections.<List<String>>emptyList());
    }

    /** 是否放行 */
    public boolean isAllowed() {
        return allowed;
    }

    /** 放行时的规范命令串；拒绝时为 null */
    public String getCanonicalCommand() {
        return canonicalCommand;
    }

    /** 拒绝原因；放行时为 null */
    public RejectReason getReason() {
        return reason;
    }

    /** 拒绝细节；可能为 null */
    public String getDetail() {
        return detail;
    }

    /** 管道各段（审计用）；拒绝时为空列表 */
    public List<List<String>> getStages() {
        return stages;
    }
}
