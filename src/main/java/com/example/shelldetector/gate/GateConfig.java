package com.example.shelldetector.gate;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 从外部配置构建 {@link CommandGate}。
 * <p>
 * 把<b>部署相关、常变</b>的受信脚本前缀外部化为配置（properties），运维可改、无需改代码：
 * </p>
 * <pre>
 * gate.sh.scripts=/home/example/validate-*.sh,/opt/app/check-*.sh
 * </pre>
 * <p>
 * <b>设计取向</b>：仅脚本前缀走外部配置；安全关键的命令白名单与参数策略仍固化在受评审的
 * 代码中，避免有人通过配置悄悄放进 {@code sh}/{@code rm} 等高危命令。
 * </p>
 */
public final class GateConfig {

    /** 受信脚本前缀（逗号分隔的 glob 列表），如 /home/example/validate-*.sh */
    public static final String KEY_SH_SCRIPTS = "gate.sh.scripts";

    private GateConfig() {
    }

    /**
     * 从 {@link Properties} 构建网关。
     */
    public static CommandGate fromProperties(Properties props) {
        CommandGate.Builder builder = CommandGate.builder();
        List<String> globs = parseList(props.getProperty(KEY_SH_SCRIPTS, ""));
        if (!globs.isEmpty()) {
            builder.allowShScripts(globs);
        }
        return builder.build();
    }

    /**
     * 从 properties 格式的输入流构建网关（UTF-8）。调用方负责打开/关闭流。
     */
    public static CommandGate fromStream(InputStream in) throws IOException {
        Properties props = new Properties();
        try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            props.load(reader);
        }
        return fromProperties(props);
    }

    /**
     * 从 properties 配置文件路径构建网关（UTF-8）。
     */
    public static CommandGate fromFile(String path) throws IOException {
        try (InputStream in = Files.newInputStream(Paths.get(path))) {
            return fromStream(in);
        }
    }

    /**
     * 解析逗号分隔列表，去空白并丢弃空项。
     */
    static List<String> parseList(String csv) {
        List<String> result = new ArrayList<>();
        if (csv == null) {
            return result;
        }
        for (String part : csv.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
