package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 差分测试 - 用真实的 /bin/sh 验证 {@link ShellQuoter} 的转义正确性。
 * <p>
 * 直接攻击 parser-executor 鸿沟：把每个参数转义后交给真实 shell 拆词，断言 shell 拆出的
 * 参数与我们的输入逐一相等——即转义后的内容在 shell 眼里只是单个字面量，元字符全部失效。
 * </p>
 * <p>
 * 只执行 {@code printf}（安全 builtin），绝不执行被测命令本身。仅在类 Unix 系统启用。
 * </p>
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
class DifferentialShellTest {

    @Test
    void testCraftedNastyArgsRoundTripThroughShell() throws Exception {
        List<String> args = Arrays.asList(
                "nginx",
                "a b",
                "x'y",
                "$(reboot)",
                "`reboot`",
                "; rm -rf /",
                "a|b",
                "--output=/etc/passwd",
                "back\\slash",
                "tab\there",
                "",
                "你好",
                "a\"b\"c",
                "${IFS}"
        );
        assertEquals(args, shellSplit(args));
    }

    @Test
    void testFuzzedArgsRoundTripThroughShell() throws Exception {
        Random rnd = new Random(2024);
        char[] pool = "abc012 \t|'\";&$`()<>{}*?!~\\[]#-_/.=\n".toCharArray();
        List<String> args = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            int len = rnd.nextInt(10);
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < len; j++) {
                sb.append(pool[rnd.nextInt(pool.length)]);
            }
            args.add(sb.toString());
        }
        // 一次 sh 调用验证全部参数
        assertEquals(args, shellSplit(args));
    }

    @Test
    void testCanonicalPipelineExecutesAsIntended() throws Exception {
        CommandGate gate = CommandGate.createDefault();

        // 单命令：含元字符的参数必须作为字面量传给 echo，而非被 shell 解释
        assertCanonicalOutput(gate, "echo 'a;b' c", "a;b c\n");
        assertCanonicalOutput(gate, "echo 'x|y' 'z>w'", "x|y z>w\n");
        // 管道：echo | cat 端到端跑通，命令词被转义后仍正确执行
        assertCanonicalOutput(gate, "echo hello | cat", "hello\n");
    }

    /** 校验输入经网关放行后，其规范串交给真实 /bin/sh 执行的输出符合预期 */
    private static void assertCanonicalOutput(CommandGate gate, String input, String expected) throws Exception {
        GateResult r = gate.validate(input);
        assertTrue(r.isAllowed(), "应放行: " + input);
        Process p = new ProcessBuilder("/bin/sh", "-c", r.getCanonicalCommand())
                .redirectErrorStream(false).start();
        String out = new String(readAll(p.getInputStream()), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(10, TimeUnit.SECONDS), "sh 执行超时");
        assertEquals(0, p.exitValue(), "sh 退出码非 0");
        assertEquals(expected, out, "规范串执行输出不符: " + r.getCanonicalCommand());
    }

    /**
     * 用 ShellQuoter 转义每个参数，交给真实 /bin/sh，让 printf 把 shell 拆出的参数
     * 以 NUL 分隔打印出来，再切回列表。
     */
    private static List<String> shellSplit(List<String> args) throws Exception {
        String program = "printf '%s\\0' " + args.stream()
                .map(ShellQuoter::quote)
                .collect(Collectors.joining(" "));

        Process p = new ProcessBuilder("/bin/sh", "-c", program)
                .redirectErrorStream(false)
                .start();

        byte[] out = readAll(p.getInputStream());
        assertTrue(p.waitFor(10, TimeUnit.SECONDS), "sh 执行超时");
        assertEquals(0, p.exitValue(), "sh 退出码非 0");

        // 按 NUL 切分；每个参数后都有一个 NUL，故末尾会有一个空段需丢弃
        List<String> result = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < out.length; i++) {
            if (out[i] == 0) {
                result.add(new String(out, start, i - start, StandardCharsets.UTF_8));
                start = i + 1;
            }
        }
        return result;
    }

    private static byte[] readAll(InputStream is) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = is.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }
}
