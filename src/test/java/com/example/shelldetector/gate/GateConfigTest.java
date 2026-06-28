package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GateConfig 测试 - 验证脚本前缀可由外部配置驱动（不写死在代码逻辑中）。
 */
class GateConfigTest {

    @Test
    void testSingleScriptPatternFromProperties() {
        Properties p = new Properties();
        p.setProperty("gate.sh.scripts", "/home/example/validate-*.sh");
        CommandGate gate = GateConfig.fromProperties(p);

        assertTrue(gate.validate("sh /home/example/validate-db.sh").isAllowed());
        assertFalse(gate.validate("sh /tmp/evil.sh").isAllowed());
    }

    @Test
    void testMultipleCommaSeparatedPatternsWithSpaces() {
        Properties p = new Properties();
        p.setProperty("gate.sh.scripts", " /home/example/validate-*.sh , /opt/app/check-*.sh ");
        CommandGate gate = GateConfig.fromProperties(p);

        assertTrue(gate.validate("sh /home/example/validate-db.sh").isAllowed());
        assertTrue(gate.validate("sh /opt/app/check-health.sh").isAllowed());
        assertFalse(gate.validate("sh /opt/app/run.sh").isAllowed());
    }

    @Test
    void testNoScriptsKeyMeansShDenied() {
        CommandGate gate = GateConfig.fromProperties(new Properties());
        GateResult r = gate.validate("sh /home/example/validate-db.sh");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
        // 普通只读命令仍可用
        assertTrue(gate.validate("ps -ef | grep nginx").isAllowed());
    }

    @Test
    void testLoadFromPropertiesStream() throws Exception {
        String text = "gate.sh.scripts=/home/example/validate-*.sh\n";
        CommandGate gate = GateConfig.fromStream(
                new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
        assertTrue(gate.validate("sh /home/example/validate-db.sh").isAllowed());
    }

    @Test
    void testBuilderAcceptsCollection() {
        CommandGate gate = CommandGate.builder()
                .allowShScripts(Arrays.asList("/home/example/validate-*.sh", "/opt/check-*.sh"))
                .build();
        assertTrue(gate.validate("sh /opt/check-x.sh").isAllowed());
    }

    @Test
    void testExactChaosCommandsFromProperties() {
        Properties p = new Properties();
        // 多条以分号分隔（; 在网关内本被禁，作分隔符安全）
        p.setProperty("gate.exact.commands",
                "stress-ng --cpu 4 --timeout 60s; kill -STOP 12345");
        CommandGate gate = GateConfig.fromProperties(p);

        assertTrue(gate.validate("stress-ng --cpu 4 --timeout 60s").isAllowed());
        assertTrue(gate.validate("kill -STOP 12345").isAllowed());
        assertFalse(gate.validate("stress-ng --cpu 8 --timeout 60s").isAllowed());
    }

    @Test
    void testCommandTemplatesFromProperties() {
        Properties p = new Properties();
        p.setProperty("gate.command.templates",
                "tc qdisc add dev eth0 root netem delay {int:0..10000}ms; kill -{enum:STOP|CONT} {int}");
        CommandGate gate = GateConfig.fromProperties(p);

        assertTrue(gate.validate("tc qdisc add dev eth0 root netem delay 100ms").isAllowed());
        assertFalse(gate.validate("tc qdisc add dev eth0 root netem delay 99999ms").isAllowed());
        assertTrue(gate.validate("kill -CONT 999").isAllowed());
    }
}
