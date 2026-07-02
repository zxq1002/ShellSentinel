package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CommandGate} 结构上应线程安全：全 {@code final} 字段 + 不可变集合，
 * {@link CommandGate#validate(String)} 只用方法局部变量、不读写任何共享可变状态。
 * README 明确建议 {@code ExecGuard}/{@code CommandGate} 可作单例复用，意味着生产环境
 * 大概率被多个并发请求线程共享同一实例。本测试把这个已成立的不变量锁定为回归测试，
 * 防止未来重构（如给某个 SegmentPolicy 加缓存字段）悄悄引入共享可变状态。
 */
class CommandGateConcurrencyTest {

    @Test
    void testConcurrentValidateProducesConsistentResults() throws InterruptedException {
        CommandGate gate = CommandGate.builder()
                .allowShScript("/home/example/validate-*.sh")
                .allowExactCommands(Arrays.asList("stress-ng --cpu 4 --timeout 60s"))
                .build();

        // 输入 -> 期望是否放行，覆盖三条通道（只读白名单 / 脚本 / 混沌）与各类拒绝路径
        List<Object[]> cases = Arrays.asList(
                new Object[]{"ps -ef | grep nginx", true},
                new Object[]{"rm -rf /", false},
                new Object[]{"sh /home/example/validate-db.sh", true},
                new Object[]{"sh /tmp/evil.sh", false},
                new Object[]{"stress-ng --cpu 4 --timeout 60s", true},
                new Object[]{"stress-ng --cpu 4 --timeout 61s", false},
                new Object[]{"grep -f /tmp/x", false},
                new Object[]{"cat poke$(reboot)", false}
        );

        int threadCount = 16;
        int iterationsPerThread = 200;
        AtomicInteger mismatches = new AtomicInteger(0);

        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threadCount; t++) {
            tasks.add(() -> {
                for (int i = 0; i < iterationsPerThread; i++) {
                    for (Object[] c : cases) {
                        String raw = (String) c[0];
                        boolean expected = (Boolean) c[1];
                        GateResult r = gate.validate(raw);
                        if (r.isAllowed() != expected) {
                            mismatches.incrementAndGet();
                        }
                    }
                }
                return null;
            });
        }

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        List<Future<Void>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "并发任务未在超时内完成");

        for (Future<Void> f : futures) {
            assertDoesNotThrow(() -> f.get(), "并发调用 validate() 时线程抛出了异常");
        }
        assertEquals(0, mismatches.get(),
                "并发调用 validate() 出现与预期不符的结果，可能存在共享可变状态竞争");
    }
}
