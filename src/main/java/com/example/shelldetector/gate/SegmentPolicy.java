package com.example.shelldetector.gate;

import java.util.List;

/**
 * 一条放行通道：对单段命令给出 {@link SegmentDecision}（接受 / 拒绝 / 弃权）。
 * <p>
 * {@link CommandGate} 按固定优先级顺序依次询问各通道：首个非弃权的裁决决定该段结果；
 * 全部弃权则该段未命中任何通道，按 {@link RejectReason#COMMAND_NOT_ALLOWED} 拒绝。
 * 这样三条通道（只读白名单 / 受信脚本 / 混沌命令）各自内聚、优先级显式。
 * </p>
 */
interface SegmentPolicy {

    /**
     * @param segment 一段命令的 token：{@code [命令名, 参数...]}（已去引号）
     */
    SegmentDecision evaluate(List<String> segment);
}
