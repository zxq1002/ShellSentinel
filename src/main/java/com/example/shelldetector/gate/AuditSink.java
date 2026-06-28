package com.example.shelldetector.gate;

/**
 * 审计 sink - 接收命令网关的每一次决策（放行 / 拒绝）。
 * <p>
 * 安全工具必须可审计「为什么放行 / 为什么拒绝」。实现方可写日志、SIEM、数据库等。
 * </p>
 */
@FunctionalInterface
public interface AuditSink {

    /**
     * 记录一次网关决策。
     *
     * @param rawCommand 调用方传入的原始命令串
     * @param result     校验结果（放行含规范串，拒绝含原因）
     */
    void onDecision(String rawCommand, GateResult result);
}
