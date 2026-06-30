package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ShellQuoter 单元测试 - 验证逐参数单引号转义（等价 POSIX shell 安全转义）。
 * <p>
 * 安全契约：任意输入经 quote 包裹后，交给 shell 解析时只能被当作单个字面量参数，
 * 内部任何元字符（$ ` ; | &amp; 空格 等）都不得被 shell 重新解释。
 * </p>
 */
class ShellQuoterTest {

    @Test
    void testSimpleWordWrappedInSingleQuotes() {
        assertEquals("'nginx'", ShellQuoter.quote("nginx"));
    }

    @Test
    void testEmptyStringBecomesEmptyQuotes() {
        assertEquals("''", ShellQuoter.quote(""));
    }

    @Test
    void testInternalSingleQuoteIsEscaped() {
        // a'b  ->  'a'\''b'
        assertEquals("'a'\\''b'", ShellQuoter.quote("a'b"));
    }

    @Test
    void testCommandSubstitutionIsNeutralizedAsLiteral() {
        // 关键安全用例：$(reboot) 必须被单引号包裹成字面量，shell 不会执行
        assertEquals("'$(reboot)'", ShellQuoter.quote("$(reboot)"));
    }

    @Test
    void testMetacharactersAreNeutralized() {
        assertEquals("'; rm -rf /'", ShellQuoter.quote("; rm -rf /"));
    }

    @Test
    void testNullThrows() {
        // 安全转义唯一入口，对 null fail-loud 而非 NPE
        assertThrows(IllegalArgumentException.class, () -> ShellQuoter.quote(null));
    }
}
