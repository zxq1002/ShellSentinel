package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ExecGuard 门面测试 - 验证「校验 + 审计 + 返回规范串 / 拒绝」的接入行为。
 */
class ExecGuardTest {

    /** 记录型审计 sink（真实实现，非 mock 框架），用于断言审计行为 */
    private static final class RecordingSink implements AuditSink {
        final List<String> raws = new ArrayList<>();
        final List<GateResult> results = new ArrayList<>();

        @Override
        public void onDecision(String rawCommand, GateResult result) {
            raws.add(rawCommand);
            results.add(result);
        }
    }

    @Test
    void testAllowedCommandReturnsCanonicalAndAudits() throws Exception {
        RecordingSink sink = new RecordingSink();
        ExecGuard guard = new ExecGuard(CommandGate.createDefault(), sink);

        String canonical = guard.canonicalOrThrow("ps -ef | grep nginx");

        assertEquals("'ps' '-ef' | 'grep' 'nginx'", canonical);
        // 审计恰好记录一次，且为放行
        assertEquals(1, sink.results.size());
        assertTrue(sink.results.get(0).isAllowed());
        assertEquals("ps -ef | grep nginx", sink.raws.get(0));
    }

    @Test
    void testRejectedCommandThrowsAndAudits() {
        RecordingSink sink = new RecordingSink();
        ExecGuard guard = new ExecGuard(CommandGate.createDefault(), sink);

        CommandRejectedException ex = assertThrows(CommandRejectedException.class,
                () -> guard.canonicalOrThrow("rm -rf /"));

        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, ex.getReason());
        // 审计恰好记录一次，且为拒绝
        assertEquals(1, sink.results.size());
        assertFalse(sink.results.get(0).isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, sink.results.get(0).getReason());
    }

    @Test
    void testInspectReturnsResultWithoutThrowing() {
        RecordingSink sink = new RecordingSink();
        ExecGuard guard = new ExecGuard(CommandGate.createDefault(), sink);

        GateResult r = guard.inspect("cat $(reboot)");

        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
        assertEquals(1, sink.results.size());
    }

    @Test
    void testCreateDefaultUsesSlf4jSinkAndWorks() throws Exception {
        ExecGuard guard = ExecGuard.createDefault();
        assertEquals("'df' '-h'", guard.canonicalOrThrow("df -h"));
    }
}
