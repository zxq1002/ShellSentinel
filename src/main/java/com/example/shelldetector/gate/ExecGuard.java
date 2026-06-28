package com.example.shelldetector.gate;

/**
 * 命令网关门面 - 平台 exec 接口的接入点。
 * <p>
 * 调用方应以本类替代「直接把原始串拼进 {@code sh -c}」：每次调用都会校验、审计，
 * 并在放行时返回<b>重建后的规范串</b>。平台必须执行该规范串，而非原始串——这是架构红线。
 * </p>
 */
public final class ExecGuard {

    private final CommandGate gate;
    private final AuditSink auditSink;

    /**
     * @param gate      命令网关
     * @param auditSink 审计 sink
     */
    public ExecGuard(CommandGate gate, AuditSink auditSink) {
        this.gate = gate;
        this.auditSink = auditSink;
    }

    /**
     * 创建使用默认白名单与 SLF4J 审计的门面。
     */
    public static ExecGuard createDefault() {
        return new ExecGuard(CommandGate.createDefault(), new Slf4jAuditSink());
    }

    /**
     * 校验并审计命令，返回完整结果（不抛异常）。
     *
     * @param rawCommand 原始命令串
     * @return 校验结果
     */
    public GateResult inspect(String rawCommand) {
        GateResult result = gate.validate(rawCommand);
        auditSink.onDecision(rawCommand, result);
        return result;
    }

    /**
     * 校验并审计命令；放行返回规范串，拒绝抛异常。
     *
     * @param rawCommand 原始命令串
     * @return 应交给 {@code sh -c} 执行的规范串
     * @throws CommandRejectedException 命令被拒绝
     */
    public String canonicalOrThrow(String rawCommand) throws CommandRejectedException {
        GateResult result = inspect(rawCommand);
        if (!result.isAllowed()) {
            throw new CommandRejectedException(result.getReason(), result.getDetail());
        }
        return result.getCanonicalCommand();
    }
}
