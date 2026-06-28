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
}
