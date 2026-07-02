package com.example.shelldetector.gate;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 直接针对 {@link ScriptPattern#of(String)} 静态构造的独立错误路径测试。
 * <p>
 * 之前这些错误路径只被 {@code CommandGateScriptTest} 通过
 * {@code CommandGate.Builder.allowShScript(...)} 间接覆盖——出错时不容易一眼定位
 * 是 {@code ScriptPattern} 自身哪个校验分支报的错。本类把每条 {@code of(...)} 的
 * 校验分支单独钉死，与集成测试互为补充，不是替代。
 * </p>
 */
class ScriptPatternTest {

    // ---------- 装配期拒绝 ----------

    @Test
    void testRelativePathRejected() {
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of("validate.sh"));
    }

    @Test
    void testNullRejected() {
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of(null));
    }

    @Test
    void testDotDotSegmentRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> ScriptPattern.of("/home/example/../etc/validate-*.sh"));
    }

    @Test
    void testMultipleWildcardsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of("/home/*/validate-*.sh"));
    }

    @Test
    void testWildcardSpanningDirectorySeparatorRejected() {
        // '*' 后缀里含 '/' 意味着跨目录，词法上无法安全限定匹配范围
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of("/home/example/validate-*/x.sh"));
    }

    @Test
    void testRootDirectoryTooBroadRejected() {
        // "/*" 的目录部分是根目录，等价于放行任意顶层文件，过于宽泛
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of("/*"));
    }

    @Test
    void testEmptyPrefixAndSuffixTooBroadRejected() {
        // "/usr/bin/*" 前后缀皆空，会匹配目录内任意文件
        assertThrows(IllegalArgumentException.class, () -> ScriptPattern.of("/usr/bin/*"));
    }

    // ---------- 正常构造与匹配 ----------

    @Test
    void testExactPathMatchesOnlyItself() {
        ScriptPattern p = ScriptPattern.of("/home/example/validate.sh");
        assertTrue(p.matches("/home/example/validate.sh"));
        assertFalse(p.matches("/home/example/validate.sh.bak"));
        assertFalse(p.matches("/home/example/other.sh"));
    }

    @Test
    void testPrefixGlobMatchesWithinDirOnly() {
        ScriptPattern p = ScriptPattern.of("/home/example/validate-*.sh");
        assertTrue(p.matches("/home/example/validate-db.sh"));
        assertFalse(p.matches("/home/example/sub/validate-x.sh"));
        assertFalse(p.matches("/home/example/backup.sh"));
    }

    @Test
    void testMatchesRejectsDotDotSegmentAtRuntime() {
        // matches() 自身也拒 '..' 段（装配期 of() 的检查只挡配置里的 '..'，
        // 运行期传入的实际路径同样要防）
        ScriptPattern p = ScriptPattern.of("/home/example/validate-*.sh");
        assertFalse(p.matches("/home/example/../example/validate-db.sh"));
    }

    @Test
    void testMatchesRejectsNonAbsolutePath() {
        ScriptPattern p = ScriptPattern.of("/home/example/validate-*.sh");
        assertFalse(p.matches("validate-db.sh"));
        assertFalse(p.matches(null));
    }
}
