package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ArgPolicy} 单元测试：锁定 {@code --} 选项终止符的 fail-closed 语义。
 * <p>
 * POSIX 语义下 {@code --} 之后一律是位置参数；本策略故意更严格——{@code --} 之后
 * "形似开关"的参数仍按开关校验（且不计入位置参数上限），只有在开关白名单里才放行。
 * 三方评审一致同意维持这一更保守的语义（不改为 POSIX 语义），因为 POSIX 语义会让
 * {@code --} 之后的任意 flag-lookalike 无条件放行，反而扩大攻击面。
 * </p>
 */
class ArgPolicyTest {

    @Test
    void testDoubleDashDoesNotSwitchModeToPositional() {
        // 关键场景：'i' 本身是被允许的开关字符（如 hostname 的 -I/-i），但 maxPositional=0。
        // 若 "--" 之后仍把 "-i" 当"形似开关"校验，它会因 'i' 在允许集里而放行；
        // 但真正的命令行工具在 "--" 之后会把它当位置参数处理（改主机名），造成写操作绕过。
        ArgPolicy policy = ArgPolicy.allow(new HashSet<>(Arrays.asList('i')), Collections.<String>emptySet(), 0);
        String violation = policy.firstViolation(Arrays.asList("--", "-i"));
        assertNotNull(violation, "-- 之后的 \"-i\" 须被计入位置参数并触发 maxPositional=0 的上限校验");
        assertEquals("-i", violation);
    }

    @Test
    void testDoubleDashAloneIsHarmless() {
        ArgPolicy policy = ArgPolicy.allow(Collections.<Character>emptySet(), Collections.<String>emptySet(), 0);
        assertNull(policy.firstViolation(Arrays.asList("--")));
    }

    @Test
    void testDoubleDashDoesNotBypassPositionalLimit() {
        // -- 之后的普通位置参数仍须计入 maxPositional
        ArgPolicy policy = ArgPolicy.allow(Collections.<Character>emptySet(), Collections.<String>emptySet(), 0);
        String violation = policy.firstViolation(Arrays.asList("--", "plainarg"));
        assertNotNull(violation);
        assertEquals("plainarg", violation);
    }
}
