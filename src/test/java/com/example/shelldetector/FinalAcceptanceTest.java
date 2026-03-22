package com.example.shelldetector;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.parser.ParserType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class FinalAcceptanceTest {

    @Test
    @DisplayName("验证 1: ANTLR 模式下的重定向符还原 (紧凑格式)")
    void testAntlrRedirectionRestoration() {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.ANTLR).build())
                .withDefaultRules()
                .build();
        
        // 2>&1 不应被误拆为 "2 > & 1"
        // 且由于它是安全的重定向，不应命中内置的 "file write redirection" (\\s*>\\s*[^\\s])
        // 验证它不会报错
        assertDoesNotThrow(() -> detector.detect("ls 2>&1"));
        
        // 验证危险重定向仍被拦截
        DetectionResult result = detector.detect("echo 'evil' > /etc/shadow");
        assertFalse(result.isPassed(), "Dangerous redirection MUST be blocked in ANTLR mode");
    }

    @Test
    @DisplayName("验证 2: 误报控制 (单词边界 \b 校验)")
    void testFalsePositiveControl() {
        ShellDetector detector = ShellDetector.createDefault();
        
        // "category" 包含 "cat"，但不应命中 "cat" 规则
        DetectionResult result = detector.detect("ls category");
        assertTrue(result.isPassed(), "'category' should not trigger 'cat' rule due to \\b");
        
        // "firmware" 包含 "rm"，但不应命中 "rm" 规则
        DetectionResult result2 = detector.detect("ls firmware");
        assertTrue(result2.isPassed(), "'firmware' should not trigger 'rm' rule due to \\b");
    }

    @Test
    @DisplayName("验证 3: 子 Shell 深度拦截 (ANTLR 模式)")
    void testAntlrSubshellDefense() {
        ShellDetector detector = ShellDetector.builder()
                .withConfig(DetectionConfig.builder().parserType(ParserType.ANTLR).build())
                .withDefaultRules()
                .build();
        
        DetectionResult result = detector.detect("echo $(rm -rf /)");
        assertFalse(result.isPassed(), "Recursive rm in subshell MUST be blocked in ANTLR mode");
    }

    @Test
    @DisplayName("验证 4: 枚举解析容错性")
    void testEnumRobustness() {
        // 模拟 JSON 中出现小写 "danger"
        assertEquals(com.example.shelldetector.model.RiskLevel.DANGER, 
                     com.example.shelldetector.model.RiskLevel.safeValueOf("danger"));
        
        // 模拟拼写错误 "dang"，触发前缀匹配或默认值
        assertNotNull(com.example.shelldetector.model.RiskLevel.safeValueOf("invalid"));
    }
}
