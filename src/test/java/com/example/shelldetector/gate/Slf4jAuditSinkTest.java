package com.example.shelldetector.gate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * slf4j-simple 默认写 System.err；捕获它来验证净化确实生效——即便 rawCommand
 * 携带裸换行，落到日志里的也应是单行、且换行被转义可见，而非拆成多行伪造记录。
 */
class Slf4jAuditSinkTest {

    private final AuditSink sink = new Slf4jAuditSink();
    private PrintStream originalErr;
    private ByteArrayOutputStream captured;

    @BeforeEach
    void redirectErr() {
        originalErr = System.err;
        captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreErr() {
        System.setErr(originalErr);
    }

    @Test
    void testRejectWithEmbeddedNewlineStaysSingleLine() {
        String raw = "grep 'foo\nFAKE LOG LINE' file";
        GateResult result = GateResult.reject(RejectReason.FORBIDDEN_SYNTAX, "\\n");

        sink.onDecision(raw, result);

        String output = captured.toString(StandardCharsets.UTF_8);
        long lineCount = output.chars().filter(c -> c == '\n').count();
        assertEquals(1, lineCount, "净化后应仅有一行日志（末尾换行），不应被裸换行拆成多行");
        assertFalse(output.contains("FAKE LOG LINE\n"), "不应出现可被解读为独立日志行的裸换行");
        assertTrue(output.contains("\\x0a"), "换行应以可见转义形式出现在日志里");
    }

    @Test
    void testAllowLogsSanitizedCanonical() {
        GateResult result = GateResult.allow("'grep' 'nginx'", java.util.Collections.emptyList());

        sink.onDecision("grep nginx", result);

        String output = captured.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("ALLOW"));
        assertTrue(output.contains("'grep' 'nginx'"));
    }
}
