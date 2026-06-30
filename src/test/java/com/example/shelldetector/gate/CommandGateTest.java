package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CommandGate 结构性安全测试。
 * <p>
 * 网关采用 default-deny：只放行「白名单命令组成的纯管道」，并把放行结果重建为
 * 逐参数转义的规范串。本测试覆盖形状校验、命令白名单、以及一批已知绕过样本。
 * </p>
 */
class CommandGateTest {

    private final CommandGate gate = CommandGate.createDefault();

    // ---------- 应放行（ALLOW），且规范串语义一致 ----------

    @Test
    void testSingleAllowedCommandPasses() {
        GateResult r = gate.validate("ps -ef");
        assertTrue(r.isAllowed());
        assertEquals("'ps' '-ef'", r.getCanonicalCommand());
    }

    @Test
    void testAllowedPipelinePasses() {
        GateResult r = gate.validate("ps -ef | grep nginx");
        assertTrue(r.isAllowed());
        assertEquals("'ps' '-ef' | 'grep' 'nginx'", r.getCanonicalCommand());
    }

    @Test
    void testQuotedArgumentPreserved() {
        GateResult r = gate.validate("'grep' 'hello world'");
        assertTrue(r.isAllowed());
        assertEquals("'grep' 'hello world'", r.getCanonicalCommand());
    }

    // ---------- 应拒绝（REJECT）：已知绕过样本 ----------

    @Test
    void testCommandNotInAllowlistRejected() {
        GateResult r = gate.validate("rm -rf /");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testPipeToShellRejected() {
        // 管道末段是 sh：白名单结构性拦截，无需枚举危险管道
        GateResult r = gate.validate("ps -ef | sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testCommandChainingRejected() {
        GateResult r = gate.validate("ps -ef; reboot");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testLogicalAndRejected() {
        GateResult r = gate.validate("ps -ef && reboot");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testCommandSubstitutionRejected() {
        GateResult r = gate.validate("cat poke$(reboot)");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testBacktickSubstitutionRejected() {
        GateResult r = gate.validate("cat `reboot`");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testRedirectionRejected() {
        GateResult r = gate.validate("grep x /etc/hosts > /tmp/out");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testBackgroundOperatorRejected() {
        GateResult r = gate.validate("ps -ef & reboot");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testNewlineRejected() {
        GateResult r = gate.validate("ps -ef\nreboot");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
    }

    @Test
    void testTooLongRejected() {
        StringBuilder sb = new StringBuilder("grep ");
        for (int i = 0; i < 5000; i++) {
            sb.append('a');
        }
        GateResult r = gate.validate(sb.toString());
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.TOO_LONG, r.getReason());
    }

    @Test
    void testNullRejected() {
        GateResult r = gate.validate(null);
        assertFalse(r.isAllowed());
    }

    @Test
    void testEmptyRejected() {
        GateResult r = gate.validate("   ");
        assertFalse(r.isAllowed());
    }

    // ---------- 参数策略：白名单命令的危险开关 ----------

    @Test
    void testGrepFileFlagRejected() {
        // grep -f 读取可控的模式文件，禁用
        GateResult r = gate.validate("grep -f /tmp/patterns x");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testGrepPerlRegexpRejectedForReDoS() {
        // -P 启用 PCRE，易构造灾难性回溯，禁用
        GateResult r = gate.validate("ps -ef | grep -P nginx");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testGrepLongFileFlagRejected() {
        GateResult r = gate.validate("grep --file=/tmp/p x");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testSortRemovedFromAllowlist() {
        // sort 含 --compress-program（任意程序执行）等危险开关，已整体移出白名单
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED,
                gate.validate("sort -u /etc/hosts").getReason());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED,
                gate.validate("sort --compress-program=sh /etc/hosts").getReason());
    }

    @Test
    void testDateRemovedFromAllowlist() {
        // date 含 -s 改时钟、-f 读任意文件，已整体移出白名单
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED,
                gate.validate("date +%Y").getReason());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED,
                gate.validate("date -f /etc/shadow").getReason());
    }

    @Test
    void testCombinedShortFlagWithUnknownRejected() {
        // -if：i 在 grep 白名单，f 不在 -> 拒
        GateResult r = gate.validate("grep -if /tmp/p x");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testGrepNormalFlagStillPasses() {
        GateResult r = gate.validate("grep -i nginx");
        assertTrue(r.isAllowed());
        assertEquals("'grep' '-i' 'nginx'", r.getCanonicalCommand());
    }

    // ---------- 开关白名单：缩写绕过 / 未知开关 / 读文件开关一律拒 ----------

    @Test
    void testGrepLongAbbreviationRejected() {
        // GNU getopt_long 缩写：--pe -> --perl-regexp。白名单只认精确安全名，缩写不在 -> 拒
        assertEquals(RejectReason.ARG_NOT_ALLOWED,
                gate.validate("grep --pe nginx file").getReason());
        assertEquals(RejectReason.ARG_NOT_ALLOWED,
                gate.validate("grep --fil=/etc/shadow x").getReason());
    }

    @Test
    void testGrepUnknownLongFlagRejected() {
        assertEquals(RejectReason.ARG_NOT_ALLOWED,
                gate.validate("grep --frobnicate x").getReason());
    }

    @Test
    void testWcFiles0FromRejected() {
        // wc --files0-from 读任意文件，不在白名单 -> 拒
        assertEquals(RejectReason.ARG_NOT_ALLOWED,
                gate.validate("wc --files0-from=/etc/shadow").getReason());
        assertTrue(gate.validate("wc -l /etc/hosts").isAllowed());
    }

    @Test
    void testHostnameSetByPositionalRejected() {
        // hostname newname 修改主机名（写，经位置参数）
        GateResult r = gate.validate("hostname newname");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testHostnameReadFlagAllowed() {
        GateResult r = gate.validate("hostname -I");
        assertTrue(r.isAllowed());
        assertEquals("'hostname' '-I'", r.getCanonicalCommand());
    }

    @Test
    void testHostnamePlainAllowed() {
        GateResult r = gate.validate("'hostname'");
        assertTrue(r.isAllowed());
        assertEquals("'hostname'", r.getCanonicalCommand());
    }

    @Test
    void testTailFollowRejected() {
        GateResult r = gate.validate("tail -f /var/log/app.log");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testTailNormalAllowed() {
        GateResult r = gate.validate("tail -n 100 /var/log/app.log");
        assertTrue(r.isAllowed());
        assertEquals("'tail' '-n' '100' '/var/log/app.log'", r.getCanonicalCommand());
    }

    @Test
    void testUniqRemovedFromAllowlist() {
        // uniq 第二位置参数是输出文件（写），从白名单移除
        GateResult r = gate.validate("ps -ef | uniq");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }
}
