package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CommandGate.Builder#build()} 生命周期契约测试。
 * <p>
 * {@code builder()} 返回的是可变对象，API 上没有"只能 build 一次"的声明，调用方保留
 * Builder 引用并继续追加配置是完全自然的用法（如按环境分别派生 dev/staging/prod 网关）。
 * 已交付的 {@link CommandGate} 实例必须是不可变快照，不能被之后对 Builder 的修改静默污染。
 * </p>
 */
class CommandGateBuilderTest {

    @Test
    void testBuilderReuseDoesNotAffectBuiltScriptGate() {
        CommandGate.Builder b = CommandGate.builder();
        b.allowShScript("/home/example/validate-*.sh");
        CommandGate g1 = b.build();

        assertFalse(g1.validate("sh /home/other/x.sh").isAllowed());

        // build() 之后继续修改 Builder：不应影响已交付的 g1
        b.allowShScript("/home/other/*.sh");
        assertFalse(g1.validate("sh /home/other/x.sh").isAllowed(),
                "已交付的网关被 Builder 后续修改静默污染");

        // 新 build() 的实例应看到追加的模式
        CommandGate g2 = b.build();
        assertTrue(g2.validate("sh /home/other/x.sh").isAllowed());
    }

    @Test
    void testBuilderReuseDoesNotAffectBuiltAllowedCommands() {
        CommandGate.Builder b = CommandGate.builder();
        CommandGate g1 = b.build();

        b.allowExactCommands(Arrays.asList("stress-ng --cpu 4 --timeout 60s"));
        assertFalse(g1.validate("stress-ng --cpu 4 --timeout 60s").isAllowed(),
                "已交付的网关被 Builder 后续修改静默污染");
    }
}
