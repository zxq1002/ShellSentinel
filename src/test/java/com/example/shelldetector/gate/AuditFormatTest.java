package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 审计日志展示层净化：即便 {@link CommandGate} 已在解析阶段拒绝控制字符，REJECT 结果里的
 * rawCommand 仍是攻击者原样输入（网关正是因为它含控制字符才拒绝的），必须在写日志前兜底转义。
 */
class AuditFormatTest {

    @Test
    void testNullPassthrough() {
        assertNull(AuditFormat.sanitize(null));
    }

    @Test
    void testPlainStringUnchanged() {
        assertEquals("grep -i nginx", AuditFormat.sanitize("grep -i nginx"));
    }

    @Test
    void testNewlineEscaped() {
        String result = AuditFormat.sanitize("foo\nFAKE LOG LINE");
        assertFalse(result.contains("\n"), "净化后不应再含裸换行");
        assertTrue(result.contains("\\x0a"));
    }

    @Test
    void testCarriageReturnEscaped() {
        String result = AuditFormat.sanitize("foo\rFAKE");
        assertFalse(result.contains("\r"));
        assertTrue(result.contains("\\x0d"));
    }

    @Test
    void testOtherControlCharsEscaped() {
        assertTrue(AuditFormat.sanitize("a" + (char) 0x0B + "b").contains("\\x0b"));
        assertTrue(AuditFormat.sanitize("a" + (char) 0x0C + "b").contains("\\x0c"));
        assertTrue(AuditFormat.sanitize("a" + (char) 0x7F + "b").contains("\\x7f"));
    }

    @Test
    void testLongStringTruncated() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append('a');
        }
        String result = AuditFormat.sanitize(sb.toString());
        assertTrue(result.length() < 500);
        assertTrue(result.endsWith("...(truncated)"));
    }

    @Test
    void testShortStringNotTruncated() {
        String result = AuditFormat.sanitize("short");
        assertEquals("short", result);
    }
}
