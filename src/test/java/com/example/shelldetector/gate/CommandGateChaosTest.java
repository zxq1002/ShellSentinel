package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 混沌注入命令白名单测试。
 * <p>
 * 故障注入命令本质危险，不能按命令名放行；只放行<b>预先登记的整条命令</b>：
 * 精确整行匹配（最严格）或带类型占位符的模板（结构钉死、占位符受校验）。
 * </p>
 */
class CommandGateChaosTest {

    // ---------- 精确整行 ----------

    private final CommandGate exactGate = CommandGate.builder()
            .allowExactCommands(Arrays.asList(
                    "stress-ng --cpu 4 --timeout 60s",
                    "kill -STOP 12345"))
            .build();

    @Test
    void testExactCommandAllowed() {
        GateResult r = exactGate.validate("stress-ng --cpu 4 --timeout 60s");
        assertTrue(r.isAllowed());
        assertEquals("'stress-ng' '--cpu' '4' '--timeout' '60s'", r.getCanonicalCommand());
    }

    @Test
    void testExactRejectsDifferentParam() {
        assertFalse(exactGate.validate("stress-ng --cpu 8 --timeout 60s").isAllowed());
    }

    @Test
    void testExactRejectsAppendedExtraArg() {
        // 借精确命令前缀拼接额外参数必须被拒
        GateResult r = exactGate.validate("stress-ng --cpu 4 --timeout 60s --vm 4");
        assertFalse(r.isAllowed());
    }

    @Test
    void testExactPipeToDangerousRejected() {
        // 精确命令后接管道执行其它命令应被拒（reboot 不在任何白名单）
        assertFalse(exactGate.validate("stress-ng --cpu 4 --timeout 60s | reboot").isAllowed());
    }

    // ---------- 模板 + 类型占位符 ----------

    private final CommandGate tplGate = CommandGate.builder()
            .allowCommandTemplates(Arrays.asList(
                    "tc qdisc add dev eth0 root netem delay {int:0..10000}ms",
                    "stress-ng --cpu {int:1..16} --timeout {int:1..300}s",
                    "kill -{enum:STOP|CONT|TERM} {int}"))
            .build();

    @Test
    void testTemplateInRangeAllowed() {
        GateResult r = tplGate.validate("tc qdisc add dev eth0 root netem delay 100ms");
        assertTrue(r.isAllowed());
        assertEquals("'tc' 'qdisc' 'add' 'dev' 'eth0' 'root' 'netem' 'delay' '100ms'",
                r.getCanonicalCommand());
    }

    @Test
    void testTemplateOutOfRangeRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem delay 99999ms").isAllowed());
    }

    @Test
    void testTemplateStructureMismatchRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem loss 50%").isAllowed());
    }

    @Test
    void testTemplateNonNumericRejected() {
        assertFalse(tplGate.validate("tc qdisc add dev eth0 root netem delay XXms").isAllowed());
    }

    @Test
    void testTemplateCpuBounds() {
        assertTrue(tplGate.validate("stress-ng --cpu 8 --timeout 30s").isAllowed());
        assertFalse(tplGate.validate("stress-ng --cpu 32 --timeout 30s").isAllowed());
    }

    @Test
    void testTemplateEnumAndInt() {
        assertTrue(tplGate.validate("kill -CONT 999").isAllowed());
        assertFalse(tplGate.validate("kill -KILL 999").isAllowed()); // KILL 不在枚举
        assertFalse(tplGate.validate("kill -STOP abc").isAllowed()); // abc 非 int
    }

    // ---------- 边界 ----------

    @Test
    void testUnmatchedIsCommandNotAllowed() {
        GateResult r = tplGate.validate("stress-ng --cpu 4 --bogus");
        assertFalse(r.isAllowed());
        assertEquals(RejectReason.COMMAND_NOT_ALLOWED, r.getReason());
    }

    @Test
    void testDefaultGateRejectsChaos() {
        assertFalse(CommandGate.createDefault()
                .validate("stress-ng --cpu 4 --timeout 60s").isAllowed());
    }

    @Test
    void testChaosCoexistsWithReadOnlyPipeline() {
        // 只读命令仍正常
        assertTrue(exactGate.validate("ps -ef | grep nginx").isAllowed());
    }

    @Test
    void testChaosTakesPrecedenceOverAllowlistArgPolicy() {
        // tail 在只读白名单且其策略禁 -f；运维把 `tail -f ...` 显式登记为混沌命令 -> 应放行
        CommandGate g = CommandGate.builder()
                .allowExactCommands(Arrays.asList("tail -f /var/log/app.log"))
                .build();
        assertTrue(g.validate("tail -f /var/log/app.log").isAllowed());
        // 未登记的 tail -f 仍被只读参数策略拒
        assertEquals(RejectReason.ARG_NOT_ALLOWED,
                g.validate("tail -f /other.log").getReason());
    }

    @Test
    void testExactChaosCommandWithQuotedSpaceArgMatches() {
        // 配置与输入须用同一套 quote-aware 分词，带空格/引号的混沌参数才能匹配
        CommandGate g = CommandGate.builder()
                .allowExactCommands(Arrays.asList("mytool --msg 'hello world'"))
                .build();
        GateResult r = g.validate("mytool --msg 'hello world'");
        assertTrue(r.isAllowed());
        assertEquals("'mytool' '--msg' 'hello world'", r.getCanonicalCommand());
    }

    @Test
    void testCommandWordWithMetacharIsQuotedInCanonical() {
        // 防御：即便运维误配了含元字符的命令词，攻击者借引号命中后，
        // 命令词在规范串中也必须被转义为字面量（不会被 shell 二次解释为命令分隔）
        CommandGate g = CommandGate.builder()
                .allowExactCommands(Arrays.asList("foo;bar baz"))
                .build();
        GateResult r = g.validate("'foo;bar' baz");
        assertTrue(r.isAllowed());
        assertEquals("'foo;bar' 'baz'", r.getCanonicalCommand());
    }

    // ---------- 配置期高危字面量兜底：tokens[0] 是间接执行器/解释器一律拒 ----------

    @Test
    void testExactCommandWithShellInterpreterRejectedAtConfigTime() {
        // 整行虽是精确登记，但 tokens[0]==sh 本身就是机器可判定的高危信号：
        // 一旦命中就等价于把 sh 的执行权限交给了配置，必须在装配期 fail-fast
        CommandGate.Builder builder = CommandGate.builder()
                .allowExactCommands(Arrays.asList("sh -c 'reboot'"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testExactCommandWithVariousInterpretersRejectedAtConfigTime() {
        for (String dangerous : new String[]{
                "bash -c id", "dash -c id", "ash -c id", "env sh -c id",
                "sudo id", "xargs id", "eval id", "exec id", "nohup id"}) {
            CommandGate.Builder builder = CommandGate.builder()
                    .allowExactCommands(Arrays.asList(dangerous));
            assertThrows(IllegalArgumentException.class, builder::build,
                    "应在装配期拒绝: " + dangerous);
        }
    }

    @Test
    void testCommandTemplateWithShellInterpreterRejectedAtConfigTime() {
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("sh -c {enum:reboot|halt}"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testNonDangerousExactCommandsStillBuildFine() {
        // 回归：正常混沌命令不受影响
        assertDoesNotThrow(() -> CommandGate.builder()
                .allowExactCommands(Arrays.asList("stress-ng --cpu 4 --timeout 60s"))
                .build());
    }

    @Test
    void testExactCommandWithAbsolutePathInterpreterRejectedAtConfigTime() {
        // basename 归一化：黑名单只按裸名字符串精确比对时，'/bin/sh' 这种绝对路径写法
        // 能无意（甚至有意）绕过 tokens[0]==sh 的检查——很多人写脚本习惯用绝对路径，
        // 不需要任何恶意就能让"保留意见 A"要求的代码评审门槛形同虚设
        CommandGate.Builder builder = CommandGate.builder()
                .allowExactCommands(Arrays.asList("/bin/sh -c 'reboot'"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testExactCommandWithRelativePathInterpreterRejectedAtConfigTime() {
        for (String dangerous : new String[]{"./sh -c id", "../bin/bash -c id", "/usr/bin/env sh -c id"}) {
            CommandGate.Builder builder = CommandGate.builder()
                    .allowExactCommands(Arrays.asList(dangerous));
            assertThrows(IllegalArgumentException.class, builder::build,
                    "应在装配期拒绝: " + dangerous);
        }
    }

    @Test
    void testCommandTemplateWithAbsolutePathInterpreterRejectedAtConfigTime() {
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("/bin/sh -c {enum:reboot|halt}"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testNonDangerousCommandWithSlashInNameStillBuildsFine() {
        // 回归：basename 归一化不应误伤"命令名本身含 /"但末段不是危险解释器名的合法登记
        // （如某些工具确以路径形式注册，只要末段 basename 不在黑名单里）
        assertDoesNotThrow(() -> CommandGate.builder()
                .allowExactCommands(Arrays.asList("/opt/tools/stress-ng --cpu 4 --timeout 60s"))
                .build());
    }

    @Test
    void testCommandTemplateWithPlaceholderInTokenZeroRejectedAtConfigTime() {
        // ultrareview 发现：tokens[0] 黑名单只比对字面量字符串，模板里 tokens[0] 可以是
        // {enum:sh|bash} 这样的占位符——它不等于黑名单里任何裸名字符串，装配期悄悄放行，
        // 但 CommandTemplate.of 随后把它编译成能匹配 "sh"/"bash" 的正则，运行期
        // "sh -c reboot" 就会被当作合法混沌命令放行，规范串变成 'sh' '-c' 'reboot'。
        // 模板没有 allowDangerousCommand 逃生舱，这是一条纯配置文件编辑就能达成的
        // sh -c 执行通道，必须在装配期堵死。
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("{enum:sh|bash} -c {enum:reboot|halt}"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testCommandTemplateWithIntPlaceholderInTokenZeroRejectedAtConfigTime() {
        // {int} 占位符同样不该作为命令名出现在 tokens[0]（数字永远不会命中黑名单里的裸名，
        // 但把命令名本身模板化已经偏离"tokens[0] 应是已知字面量命令名"的设计前提）
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("{int} -c reboot"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testCommandTemplateWithNonDangerousEnumTokenZeroAlsoRejected() {
        // tokens[0] 含占位符一律拒绝（而不是只挡危险的枚举值），是刻意的宽泛拒绝：
        // tokens[0] 应是已知字面量命令名，不该是模板变量——即便这里的枚举值
        // （kill/pkill）本身并不危险，也一并拒绝，运维须拆成两条模板分别登记
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("{enum:kill|pkill} -{enum:STOP|CONT|TERM} {int}"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testCommandTemplateWithLiteralTokenZeroStillBuildsFine() {
        // 回归：tokens[0] 是纯字面量（无占位符）时不受影响，只有 tokens[0] 含 '{' 才拒绝
        assertDoesNotThrow(() -> CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("kill -{enum:STOP|CONT|TERM} {int}"))
                .build());
    }

    // ---------- 配置期高危字面量兜底：未闭合引号一律拒 ----------

    @Test
    void testExactCommandWithUnclosedQuoteRejectedAtConfigTime() {
        // 未闭合引号会让 CommandTokenizer 静默吞掉后续内容，产出一条运维没料到的死配置；
        // 与 ScriptPattern.of 拒绝 '..' 段同一防御哲学：装配期直接 fail-fast
        CommandGate.Builder builder = CommandGate.builder()
                .allowExactCommands(Arrays.asList("stress-ng --cpu 'abc"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testCommandTemplateWithUnclosedQuoteRejectedAtConfigTime() {
        CommandGate.Builder builder = CommandGate.builder()
                .allowCommandTemplates(Arrays.asList("tc qdisc add 'dev {int}"));
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void testAllowDangerousCommandExplicitOverrideBypassesBlacklist() {
        // 运维显式表达意图的旁路：仅放行该字面量本身，不放行 sh 的其它任意用法
        CommandGate g = CommandGate.builder()
                .allowDangerousCommand("sh /opt/chaos/kill-network.sh")
                .build();
        assertTrue(g.validate("sh /opt/chaos/kill-network.sh").isAllowed());
        assertFalse(g.validate("sh -c 'reboot'").isAllowed());
    }
}
