package com.example.shelldetector.gate;

/**
 * 受信脚本路径模式。
 * <p>
 * 由形如 {@code /home/example/validate-*.sh} 的 glob 配置而来：恰好一个 {@code *}，
 * 拆分为「目录 + 文件名前缀 + 文件名后缀」。{@code *} 不跨目录分隔符。
 * </p>
 * <p>
 * 匹配是纯词法的：要求绝对路径、无 {@code ..} 段、父目录精确等于配置目录、
 * 文件名前后缀匹配。<b>注意</b>：词法匹配无法防止「同名文件被替换 / 软链」——
 * 在脚本目录可写的环境下，须用文件系统权限保证该目录不可被 exec 用户写入。
 * </p>
 */
public final class ScriptPattern {

    private final String dir;
    private final String filePrefix;
    private final String fileSuffix;

    private ScriptPattern(String dir, String filePrefix, String fileSuffix) {
        this.dir = dir;
        this.filePrefix = filePrefix;
        this.fileSuffix = fileSuffix;
    }

    /**
     * 从 glob 配置构造，如 {@code /home/example/validate-*.sh}。
     *
     * @throws IllegalArgumentException glob 非法（须为绝对路径、恰好一个 {@code *}、{@code *} 不跨 /）
     */
    public static ScriptPattern of(String glob) {
        if (glob == null || !glob.startsWith("/")) {
            throw new IllegalArgumentException("脚本模式必须为绝对路径: " + glob);
        }
        int star = glob.indexOf('*');
        if (star < 0 || glob.indexOf('*', star + 1) >= 0) {
            throw new IllegalArgumentException("脚本模式必须恰好包含一个 '*': " + glob);
        }
        String before = glob.substring(0, star);
        String suffix = glob.substring(star + 1);
        if (suffix.indexOf('/') >= 0) {
            throw new IllegalArgumentException("'*' 不可跨目录分隔符: " + glob);
        }
        int slash = before.lastIndexOf('/');
        String dir = before.substring(0, slash);
        String filePrefix = before.substring(slash + 1);
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
        int slash = path.lastIndexOf('/');
        String parent = path.substring(0, slash);
        String filename = path.substring(slash + 1);
        return parent.equals(dir)
                && filename.startsWith(filePrefix)
                && filename.endsWith(fileSuffix)
                && filename.length() >= filePrefix.length() + fileSuffix.length();
    }
}
