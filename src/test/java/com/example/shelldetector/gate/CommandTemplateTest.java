package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 直接针对 {@link CommandTemplate#of(String)} 静态构造的独立错误路径测试。
 * <p>
 * 之前这些错误路径只被 {@code CommandGateChaosTest} 通过
 * {@code CommandGate.Builder.allowCommandTemplates(...)} 间接覆盖——出错时不容易一眼
 * 定位是 {@code CommandTemplate} 自身哪个占位符解析分支报的错。本类把每条 {@code of(...)}
 * 的校验分支单独钉死，与集成测试互为补充，不是替代。
 * </p>
 */
class CommandTemplateTest {

    // ---------- 装配期拒绝 ----------

    @Test
    void testBlankTemplateRejected() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.of("   "));
    }

    @Test
    void testUnclosedPlaceholderRejected() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.of("kill -{enum:STOP|CONT"));
    }

    @Test
    void testUnknownPlaceholderKindRejected() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.of("kill -{bogus}"));
    }

    @Test
    void testIntRangeMissingDotsRejected() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.of("kill -{int:5}"));
    }

    @Test
    void testIntRangeNonNumericBoundsRejected() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.of("kill -{int:a..b}"));
    }

    // ---------- 正常构造与匹配 ----------

    @Test
    void testPlainIntPlaceholderMatchesAnyNonNegativeInteger() {
        CommandTemplate t = CommandTemplate.of("kill -STOP {int}");
        assertTrue(t.matches(Arrays.asList("kill", "-STOP", "12345")));
        assertFalse(t.matches(Arrays.asList("kill", "-STOP", "-1")));
        assertFalse(t.matches(Arrays.asList("kill", "-STOP", "abc")));
    }

    @Test
    void testIntRangeBoundsAreInclusive() {
        CommandTemplate t = CommandTemplate.of("tc qdisc add dev eth0 root netem delay {int:0..10000}ms");
        assertTrue(t.matches(Arrays.asList("tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "0ms")));
        assertTrue(t.matches(Arrays.asList("tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "10000ms")));
        assertFalse(t.matches(Arrays.asList("tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "10001ms")));
    }

    @Test
    void testEnumPlaceholderOnlyMatchesListedValues() {
        CommandTemplate t = CommandTemplate.of("kill -{enum:STOP|CONT|TERM} {int}");
        assertTrue(t.matches(Arrays.asList("kill", "-STOP", "1")));
        assertTrue(t.matches(Arrays.asList("kill", "-TERM", "1")));
        assertFalse(t.matches(Arrays.asList("kill", "-KILL", "1")));
    }

    @Test
    void testTokenCountMismatchDoesNotMatch() {
        CommandTemplate t = CommandTemplate.of("stress-ng --cpu {int} --timeout {int}s");
        assertFalse(t.matches(Arrays.asList("stress-ng", "--cpu", "4", "--timeout", "60s", "extra")));
    }
}
