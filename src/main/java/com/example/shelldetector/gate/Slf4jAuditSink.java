package com.example.shelldetector.gate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 默认审计 sink - 通过 SLF4J 输出决策日志。
 * <p>
 * 放行记 INFO（含规范串），拒绝记 WARN（含原因与细节）。原始串一并记录以便取证。
 * 写日志前经 {@link AuditFormat#sanitize(String)} 净化（控制字符转义 + 长度上限），
 * 防止攻击者用原始串伪造日志行（CWE-117）。
 * </p>
 */
public final class Slf4jAuditSink implements AuditSink {

    private static final Logger logger = LoggerFactory.getLogger("com.example.shelldetector.audit");

    @Override
    public void onDecision(String rawCommand, GateResult result) {
        String safeRaw = AuditFormat.sanitize(rawCommand);
        if (result.isAllowed()) {
            logger.info("ALLOW raw=[{}] canonical=[{}]",
                    safeRaw, AuditFormat.sanitize(result.getCanonicalCommand()));
        } else {
            logger.warn("REJECT reason={} detail=[{}] raw=[{}]",
                    result.getReason(), AuditFormat.sanitize(result.getDetail()), safeRaw);
        }
    }
}
