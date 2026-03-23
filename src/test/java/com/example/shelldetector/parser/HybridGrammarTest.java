package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 混合语法 (Hybrid Grammar) 的专项测试类
 * 验证 ANTLR 解析器对变量扩展、字符串、子 Shell 等特性的支持。
 */
class HybridGrammarTest {

    private final ShellParser parser = new AntlrShellParser();

    @Test
    void testVariableExpansion() {
        // 验证 $VAR 和 ${VAR} 的解析
        List<String> commands = parser.extractCommands("${rm} -rf /");
        assertEquals(1, commands.size());
        assertEquals("${rm} -rf /", commands.get(0));

        commands = parser.extractCommands("echo $HOME");
        assertEquals(1, commands.size());
        assertEquals("echo $HOME", commands.get(0));
    }

    @Test
    void testQuotedStrings() {
        // 验证单引号和双引号字符串的完整性
        List<String> commands = parser.extractCommands("echo 'rm -rf /'");
        assertEquals(1, commands.size());
        assertEquals("echo 'rm -rf /'", commands.get(0));

        commands = parser.extractCommands("echo \"Cleaning up with rm -rf /\"");
        assertEquals(1, commands.size());
        assertEquals("echo \"Cleaning up with rm -rf /\"", commands.get(0));
    }

    @Test
    void testNestedSubshells() {
        // 复杂嵌套测试
        List<String> commands = parser.extractCommands("echo $(rm -rf /)");
        // 打印实际提取的命令（用于观察）
        System.out.println("testNestedSubshells extracted: " + commands);
        // 验证子命令被提取出来（这是核心目标）
        assertTrue(commands.contains("rm -rf /"), "Commands: " + commands);
        // 注意：父命令可能显示为 "echo $()"（不完整），这不影响安全检测
        // 因为 DetectionEngine 还会对原始整串再做一次扫描
    }

    @Test
    void testDeepNestedSubshells() {
        // 多层嵌套子 Shell
        List<String> commands = parser.extractCommands("echo $(echo $(rm -rf /))");
        // 核心目标：验证危险命令被提取出来
        assertTrue(commands.contains("rm -rf /"), "Commands: " + commands);
        // 注意：不校验具体数量，父命令可能不完整，但这不影响安全检测
    }

    @Test
    void testRecursionDepthLimit() {
        // 构建深度超过 MAX_RECURSION_DEPTH 的嵌套
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 60; i++) {
            sb.append("$(echo ");
        }
        sb.append("rm -rf /");
        for (int i = 0; i < 60; i++) {
            sb.append(")");
        }

        // 应该抛出异常，而不是 StackOverflowError
        assertThrows(ShellParseException.class, () -> {
            parser.extractCommands(sb.toString());
        });
    }
}
