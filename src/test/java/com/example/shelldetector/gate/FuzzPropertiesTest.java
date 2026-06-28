package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 属性/模糊测试 - 用随机输入验证识别器的若干不变量。
 * <p>
 * 这里只断言「不依赖目标 shell」的纯 Java 属性；转义对真实 shell 的正确性由
 * {@link DifferentialShellTest} 通过差分验证。
 * </p>
 */
class FuzzPropertiesTest {

    private static final CommandGate GATE = CommandGate.createDefault();

    /** 富字符池：字母数字 + 空白 + 管道 + 引号 + 各类元字符 */
    private static final char[] POOL = (
            "abcdefgABCDEFG0123 \t|'\";&$`()<>{}*?!~\\[]#-_/.=" + "\n").toCharArray();

    /** 可接受位置参数的命令子集（排除 hostname，其位置参数上限为 0） */
    private static final String[] POSITIONAL_OK = {
            "ps", "grep", "ls", "cat", "head", "wc", "stat", "df", "echo"
    };

    private static final char[] FORBIDDEN_BARE =
            ";&$`()<>{}*?!~\\[]#\n\r".toCharArray();

    @Test
    void testValidateNeverThrowsAndIsDeterministic() {
        Random rnd = new Random(42);
        for (int i = 0; i < 5000; i++) {
            String raw = randomString(rnd, 0, 30);
            GateResult a = GATE.validate(raw);            // 不得抛异常
            GateResult b = GATE.validate(raw);            // 确定性
            assertEquals(a.isAllowed(), b.isAllowed(), "非确定性: [" + raw + "]");
            assertEquals(a.getCanonicalCommand(), b.getCanonicalCommand(), "规范串不一致: [" + raw + "]");
        }
    }

    @Test
    void testBasicResultInvariants() {
        Random rnd = new Random(7);
        for (int i = 0; i < 5000; i++) {
            String raw = randomString(rnd, 0, 30);
            GateResult r = GATE.validate(raw);
            if (r.isAllowed()) {
                assertNotNull(r.getCanonicalCommand(), "放行却无规范串: [" + raw + "]");
                // 放行的每一段命令名都不得是空，且来自识别器拆出的 token
                for (java.util.List<String> stage : r.getStages()) {
                    assertFalse(stage.isEmpty());
                    assertFalse(stage.get(0).isEmpty());
                }
            } else {
                assertNotNull(r.getReason(), "拒绝却无原因: [" + raw + "]");
                assertNull(r.getCanonicalCommand());
            }
        }
    }

    @Test
    void testBareForbiddenCharAlwaysRejected() {
        for (char c : FORBIDDEN_BARE) {
            String raw = "grep " + c;            // 裸出现在引号外
            GateResult r = GATE.validate(raw);
            assertFalse(r.isAllowed(), "裸元字符未被拒绝: U+" + Integer.toHexString(c));
            assertEquals(RejectReason.FORBIDDEN_SYNTAX, r.getReason());
        }
    }

    @Test
    void testSingleQuotedPositionalContentPreservedVerbatim() {
        Random rnd = new Random(99);
        for (int i = 0; i < 3000; i++) {
            String command = POSITIONAL_OK[rnd.nextInt(POSITIONAL_OK.length)];
            // 单引号内任意字符（除单引号本身）都应原样成为逻辑值；前缀字母确保不是 flag
            String content = "x" + randomStringNoSingleQuote(rnd, 0, 12);
            GateResult r = GATE.validate(command + " '" + content + "'");
            assertTrue(r.isAllowed(), "单引号位置参数被拒: [" + content + "]");
            assertEquals(command, r.getStages().get(0).get(0));
            assertEquals(content, r.getStages().get(0).get(1), "逻辑值未原样保留: [" + content + "]");
        }
    }

    private static String randomString(Random rnd, int min, int max) {
        int len = min + rnd.nextInt(max - min + 1);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(POOL[rnd.nextInt(POOL.length)]);
        }
        return sb.toString();
    }

    private static String randomStringNoSingleQuote(Random rnd, int min, int max) {
        int len = min + rnd.nextInt(max - min + 1);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c;
            do {
                c = POOL[rnd.nextInt(POOL.length)];
            } while (c == '\'');
            sb.append(c);
        }
        return sb.toString();
    }
}
