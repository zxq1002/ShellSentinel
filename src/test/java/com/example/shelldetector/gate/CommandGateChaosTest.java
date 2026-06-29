package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 混沌注入命令白名单测试。
 * <p>
 * 故障注入命令本质危险，不能按命令名放行；只放行<b>预先登记的整条命令</b>：
 * 精确整行匹配（最严格）或带类型占位符的模板（结构钉死、占位符受校验）。
 * </p>
 */
class CommandGateChaosTest {

    // ---------- 精确整行 ----------

    private final CommandGate exactGate = CommandGate.builder()
            .allowExactCommands(Arrays.asList(
                    "stress-ng --cpu 4 --timeout 60s",
                    "kill -STOP 12345"))
            .build();

    @Test
    void testExactCommandAllowed() {
        GateResult r = exactGate.validate("stress-ng --cpu 4 --timeout 60s");
        assertTrue(r.isAllowed());
        assertEquals("'stress-ng' '--cpu' '4' '--timeout' '60s'", r.getCanonicalCommand());
    }

    @Test
    void testExactRejectsDifferentParam() {
        assertFalse(exactGate.validate("stress-ng --cpu 8 --timeout 60s").isAllowed());
    }

    @Test
    void testExactRejectsAppendedExtraArg() {
        // 借精确命令前缀拼接额外参数必须被拒
        GateResult r = exactGate.validate("stress-ng --cpu 4 --timeout 60s --vm 4");
        assertFalse(r.isAllowed());
    }

    @Test
    void testExactPipeToDangerousRejected() {
        // 精确命令后接管道执行其它命令应被拒（reboot 不在任何白名单）
        assertFalse(exactGate.validate("stress-ng --cpu 4 --timeout 60s | reboot").isAllowed());
    }

    // ---------- 模板 + 类型占位符 ----------

    private final CommandGate tplGate = CommandGate.builder()
            .allowCommandTemplates(Arrays.asList(
                    "tc qdisc add dev eth0 root netem delay {int:0..10000}ms",
                    "stress-ng --cpu {int:1..16} --timeout {int:1..300}s",
                    "kill -{enum:STOP|CONT|TERM} {int}"))
            .build();

    @Test
    void testTemplateInRangeAllowed() {
        GateResult r = tplGate.validate("tc qdisc add dev eth0 root netem delay 100ms");
        assertTrue(r.isAllowed());
        assertEquals("'tc' 'qdisc' 'add' 'dev' 'eth0' 'root' 'netem' 'delay' '100ms'",
                r.getCanonicalCommand());
    }

    @Test
    void testTemplateOutOfRangeRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem delay 99999ms").isAllowed());
    }

    @Test
    void testTemplateStructureMismatchRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem loss 50%").isAllowed());
    }

    @Test
    void testTemplateNonNumericRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem delay XXms").isAllowed());
    }

    @Test
    void testTemplateCpuBounds() {
        assertTrue(tplGate.validate("stress-ng --cpu 8 --timeout 30s").isAllowed());
        assertFalse(tplGate.validate("stress-ng --cpu 32 --timeout 30s").isAllowed());
    }

    @Test
    void testTemplateEnumAndInt() {
        assertTrue(tplGate.validate("kill -CONT 999").isAllowed());
        assertFalse(tplGate.validate("kill -KILL 999").isAllowed()); // KILL 不在枚举
        assertFalse(tplGate.validate("kill -STOP abc").isAllowed()); // abc 非 int
    }

    // ---------- 边界 ----------

    @Test
    void testUnmatchedIsCommandNotAllowed() {
        GateResult r = tplGate.validate("stress-ng --cpu 4 --bogus");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testDefaultGateRejectsChaos() {
        assertFalse(CommandGate.createDefault()
                .validate("stress-ng --cpu 4 --timeout 60s").isAllowed());
    }

    @Test
    void testChaosCoexistsWithReadOnlyPipeline() {
        // 只读命令仍正常
        assertTrue(exactGate.validate("ps -ef | grep nginx").isAllowed());
    }

    @Test
    void testCommandWordWithMetacharIsQuotedInCanonical() {
        // 防御：即便运维误配了含元字符的命令词，攻击者借引号命中后，
        // 命令词在规范串中也必须被转义为字面量（不会被 shell 二次解释为命令分隔）
        CommandGate g = CommandGate.builder()
                .allowExactCommands(Arrays.asList("foo;bar baz"))
                .build();
        GateResult r = g.validate("'foo;bar' baz");
        assertTrue(r.isAllowed());
        assertEquals("'foo;bar' 'baz'", r.getCanonicalCommand());
    }
}
