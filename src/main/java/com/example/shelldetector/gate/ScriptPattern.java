package com.example.shelldetector.gate;

/**
 * 受信脚本路径模式。
 * <p>
 * 由配置字符串构造，支持两种形式：
 * </p>
 * <ul>
 *     <li><b>精确路径</b>（无 {@code *}），如 {@code /home/example/validate.sh}：只匹配该绝对路径本身，最严格。</li>
 *     <li><b>前缀通配</b>（恰好一个 {@code *}），如 {@code /home/example/validate-*.sh}：拆分为
 *         「目录 + 文件名前缀 + 文件名后缀」，{@code *} 不跨目录分隔符。</li>
 * </ul>
 * <p>
 * 匹配是纯词法的：要求绝对路径、无 {@code ..} 段。<b>注意</b>：词法匹配无法防止
 * 「同名文件被替换 / 软链」——在脚本目录可写的环境下，须用文件系统权限保证该目录不可被 exec 用户写入。
 * </p>
 */
public final class ScriptPattern {

    private final boolean exact;
    /** 精确模式：完整路径 */
    private final String exactPath;
    /** 通配模式：目录 / 文件名前缀 / 文件名后缀 */
    private final String dir;
    private final String filePrefix;
    private final String fileSuffix;

    private ScriptPattern(String exactPath) {
        this.exact = true;
        this.exactPath = exactPath;
        this.dir = null;
        this.filePrefix = null;
        this.fileSuffix = null;
    }

    private ScriptPattern(String dir, String filePrefix, String fileSuffix) {
        this.exact = false;
        this.exactPath = null;
        this.dir = dir;
        this.filePrefix = filePrefix;
        this.fileSuffix = fileSuffix;
    }

    /**
     * 从配置构造：无 {@code *} 为精确路径，恰好一个 {@code *} 为前缀通配。
     *
     * @throws IllegalArgumentException 配置非法（须为绝对路径、{@code *} 至多一个且不跨 {@code /}）
     */
    public static ScriptPattern of(String glob) {
        if (glob == null || !glob.startsWith("/")) {
            throw new IllegalArgumentException("脚本模式必须为绝对路径: " + glob);
        }
        int first = glob.indexOf('*');
        if (first < 0) {
            // 无通配符：精确路径
            return new ScriptPattern(glob);
        }
        if (glob.indexOf('*', first + 1) >= 0) {
            throw new IllegalArgumentException("脚本模式最多包含一个 '*': " + glob);
        }
        String before = glob.substring(0, first);
        String suffix = glob.substring(first + 1);
        if (suffix.indexOf('/') >= 0) {
            throw new IllegalArgumentException("'*' 不可跨目录分隔符: " + glob);
        }
        int slash = before.lastIndexOf('/');
        String dir = before.substring(0, slash);
        if (dir.isEmpty()) {
            // 如 "/*"：目录为根，过于宽泛，拒绝
            throw new IllegalArgumentException("脚本模式目录过于宽泛: " + glob);
        }
        String filePrefix = before.substring(slash + 1);
        if (filePrefix.isEmpty() && suffix.isEmpty()) {
            // 如 /usr/bin/*：前后缀皆空会匹配目录内任意文件，过于宽泛，拒绝
            throw new IllegalArgumentException("脚本模式过于宽泛（需文件名前缀或后缀）: " + glob);
        }
        return new ScriptPattern(dir, filePrefix, suffix);
    }

    /**
     * 判断具体脚本路径是否匹配本模式。
     *
     * @param path 调用方给出的脚本路径（已去引号）
     * @return true 表示匹配
     */
    public boolean matches(String path) {
        if (path == null || !path.startsWith("/")) {
            return false;
        }
        // 拒绝任何 .. 段，避免路径穿越
        for (String segment : path.split("/")) {
            if (segment.equals("..")) {
                return false;
            }
        }
        if (exact) {
            return path.equals(exactPath);
        }
        int slash = path.lastIndexOf('/');
        String parent = path.substring(0, slash);
        String filename = path.substring(slash + 1);
        return parent.equals(dir)
                && filename.startsWith(filePrefix)
                && filename.endsWith(fileSuffix)
                && filename.length() >= filePrefix.length() + fileSuffix.length();
    }
}
