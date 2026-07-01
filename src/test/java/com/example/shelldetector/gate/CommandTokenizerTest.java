package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CommandTokenizer} 分词标准需与 {@link CommandGate} 对输入的分词标准保持一致
 * （只认 ASCII 空格 {@code ' '} 与制表符 {@code '\t'} 为分隔符），否则配置里的混沌命令
 * token 与运行时输入 token 可能因分词标准不一致而永远匹配不上。
 */
class CommandTokenizerTest {

    @Test
    void testSpaceAndTabAreSeparators() {
        assertEquals(Arrays.asList("a", "b"), CommandTokenizer.tokenize("a b"));
        assertEquals(Arrays.asList("a", "b"), CommandTokenizer.tokenize("a\tb"));
    }

    @Test
    void testOtherWhitespaceIsNotASeparator() {
        // Character.isWhitespace() 还会认可 、 等；CommandGate 不把它们当分隔符，
        // CommandTokenizer 须与之对齐，否则同一条混沌命令在配置侧和输入侧会被拆成不同的 token 数
        String withVerticalTab = "a" + (char) 0x0B + "b";
        assertEquals(Arrays.asList(withVerticalTab), CommandTokenizer.tokenize(withVerticalTab));
    }
}
