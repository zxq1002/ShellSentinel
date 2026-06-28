package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 受限脚本执行许可测试。
 * <p>
 * 仅当形如 {@code sh <匹配前缀的绝对路径脚本> [args]} 时放行；脚本路径须命中配置的
 * 目录+文件名前缀（如 /home/example/validate-*.sh），sh 的所有开关一律禁止（堵死 sh -c）。
 * </p>
 */
class CommandGateScriptTest {

    private final CommandGate gate = CommandGate.builder()
            .allowShScript("/home/example/validate-*.sh")
            .build();

    // ---------- 应放行 ----------

    @Test
    void testTrustedScriptAllowed() {
        GateResult r = gate.validate("sh /home/example/validate-db.sh");
        assertTrue(r.isAllowed());
        assertEquals("sh '/home/example/validate-db.sh'", r.getCanonicalCommand());
    }

    @Test
    void testTrustedScriptWithArgsPassedThrough() {
        GateResult r = gate.validate("sh /home/example/validate-db.sh --verbose 5");
        assertTrue(r.isAllowed());
        assertEquals("sh '/home/example/validate-db.sh' '--verbose' '5'", r.getCanonicalCommand());
    }

    @Test
    void testTrustedScriptInPipeAllowed() {
        GateResult r = gate.validate("sh /home/example/validate-db.sh | grep OK");
        assertTrue(r.isAllowed());
        assertEquals("sh '/home/example/validate-db.sh' | grep 'OK'", r.getCanonicalCommand());
    }

    @Test
    void testEmptyStarMatches() {
        GateResult r = gate.validate("sh /home/example/validate-.sh");
        assertTrue(r.isAllowed());
    }

    // ---------- 应拒绝 ----------

    @Test
    void testShCFlagRejected() {
        GateResult r = gate.validate("sh -c reboot");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testShWithoutScriptRejected() {
        GateResult r = gate.validate("sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testPipeToBareShRejected() {
        // echo allowed，但 sh 无脚本参数 -> 拒绝（防 `... | sh` 读 stdin 执行）
        GateResult r = gate.validate("echo reboot | sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testScriptOutsideDirRejected() {
        GateResult r = gate.validate("sh /tmp/validate-evil.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testPathTraversalRejected() {
        GateResult r = gate.validate("sh /home/example/../etc/validate-x.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testWrongFilePrefixRejected() {
        GateResult r = gate.validate("sh /home/example/backup.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testWrongSuffixRejected() {
        GateResult r = gate.validate("sh /home/example/validate-x.txt");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testSubdirNotMatchedByStar() {
        GateResult r = gate.validate("sh /home/example/sub/validate-x.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testRelativePathRejected() {
        GateResult r = gate.validate("sh validate-x.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.SCRIPT_NOT_ALLOWED, r.getReason());
    }

    // ---------- 精确路径（不带通配符） ----------

    @Test
    void testExactScriptPathAllowed() {
        CommandGate g = CommandGate.builder().allowShScript("/home/example/validate.sh").build();
        assertTrue(g.validate("sh /home/example/validate.sh").isAllowed());
    }

    @Test
    void testExactScriptPathRejectsLookalikes() {
        CommandGate g = CommandGate.builder().allowShScript("/home/example/validate.sh").build();
        assertFalse(g.validate("sh /home/example/validate.sh.bak").isAllowed());
        assertFalse(g.validate("sh /home/example/validate-db.sh").isAllowed());
    }

    @Test
    void testExactScriptWithArgs() {
        CommandGate g = CommandGate.builder().allowShScript("/home/example/validate.sh").build();
        GateResult r = g.validate("sh /home/example/validate.sh --verbose");
        assertTrue(r.isAllowed());
        assertEquals("sh '/home/example/validate.sh' '--verbose'", r.getCanonicalCommand());
    }

    @Test
    void testExactAndGlobCanCoexist() {
        CommandGate g = CommandGate.builder()
                .allowShScript("/home/example/validate.sh", "/opt/app/check-*.sh")
                .build();
        assertTrue(g.validate("sh /home/example/validate.sh").isAllowed());
        assertTrue(g.validate("sh /opt/app/check-health.sh").isAllowed());
    }

    @Test
    void testMultipleWildcardsRejectedAtConfig() {
        assertThrows(IllegalArgumentException.class,
                () -> CommandGate.builder().allowShScript("/home/*/validate-*.sh"));
    }

    // ---------- 默认网关不开启 sh ----------

    @Test
    void testDefaultGateStillRejectsSh() {
        GateResult r = CommandGate.createDefault().validate("sh /home/example/validate-db.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }
}
