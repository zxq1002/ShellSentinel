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
        assertEquals("ps '-ef'", r.getCanonicalCommand());
    }

    @Test
    void testAllowedPipelinePasses() {
        GateResult r = gate.validate("ps -ef | grep nginx");
        assertTrue(r.isAllowed());
        assertEquals("ps '-ef' | grep 'nginx'", r.getCanonicalCommand());
    }

    @Test
    void testQuotedArgumentPreserved() {
        GateResult r = gate.validate("grep 'hello world'");
        assertTrue(r.isAllowed());
        assertEquals("grep 'hello world'", r.getCanonicalCommand());
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
    void testSortOutputFlagRejected() {
        // sort -o 写文件
        GateResult r = gate.validate("sort -o /etc/passwd /etc/hosts");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testSortLongOutputFlagRejected() {
        GateResult r = gate.validate("sort --output=/etc/passwd /etc/hosts");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testCombinedShortFlagWithDeniedRejected() {
        // -if 含被禁的 f
        GateResult r = gate.validate("grep -if /tmp/p x");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testGrepNormalFlagStillPasses() {
        GateResult r = gate.validate("grep -i nginx");
        assertTrue(r.isAllowed());
        assertEquals("grep '-i' 'nginx'", r.getCanonicalCommand());
    }

    // ---------- 参数策略补全：写经开关 / 写经位置参数 / 长驻 ----------

    @Test
    void testDateSetFlagRejected() {
        // date -s 修改系统时间（写）
        GateResult r = gate.validate("date -s 2020-01-01");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testDateLongSetRejected() {
        GateResult r = gate.validate("date --set=2020-01-01");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.ARG_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testDateFormatAllowed() {
        GateResult r = gate.validate("date +%Y");
        assertTrue(r.isAllowed());
        assertEquals("date '+%Y'", r.getCanonicalCommand());
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
        assertEquals("hostname '-I'", r.getCanonicalCommand());
    }

    @Test
    void testHostnamePlainAllowed() {
        GateResult r = gate.validate("hostname");
        assertTrue(r.isAllowed());
        assertEquals("hostname", r.getCanonicalCommand());
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
        assertEquals("tail '-n' '100' '/var/log/app.log'", r.getCanonicalCommand());
    }

    @Test
    void testUniqRemovedFromAllowlist() {
        // uniq 第二位置参数是输出文件（写），从白名单移除
        GateResult r = gate.validate("ps -ef | uniq");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }
}
