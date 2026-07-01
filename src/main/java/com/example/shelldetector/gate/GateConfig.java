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
 * 代码中，避免有人通过配置悄悄放进 {@code sh}/{@code rm} 等高危命令。混沌命令
 * （{@link #KEY_EXACT_COMMANDS}/{@link #KEY_COMMAND_TEMPLATES}）额外有 {@link ChaosPolicy}
 * 的装配期黑名单兜底：{@code tokens[0]} 命中 {@code sh}/{@code bash}/{@code sudo} 等间接
 * 执行器会在加载时直接抛异常（fail-fast），而非悄悄加载成功。
 * </p>
 */
public final class GateConfig {

    /** 受信脚本前缀（逗号分隔的 glob 列表），如 /home/example/validate-*.sh */
    public static final String KEY_SH_SCRIPTS = "gate.sh.scripts";
    /** 混沌注入精确命令（分号分隔），如 stress-ng --cpu 4 --timeout 60s */
    public static final String KEY_EXACT_COMMANDS = "gate.exact.commands";
    /** 混沌注入命令模板（分号分隔），如 tc ... delay {int:0..10000}ms */
    public static final String KEY_COMMAND_TEMPLATES = "gate.command.templates";

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
        // 混沌命令含空格，用分号分隔（; 在网关内本被禁，作分隔符安全）
        List<String> exact = parseList(props.getProperty(KEY_EXACT_COMMANDS, ""), ";");
        if (!exact.isEmpty()) {
            builder.allowExactCommands(exact);
        }
        List<String> templates = parseList(props.getProperty(KEY_COMMAND_TEMPLATES, ""), ";");
        if (!templates.isEmpty()) {
            builder.allowCommandTemplates(templates);
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
        return parseList(csv, ",");
    }

    /**
     * 解析指定分隔符的列表，去空白并丢弃空项。
     */
    static List<String> parseList(String raw, String delimiter) {
        List<String> result = new ArrayList<>();
        if (raw == null) {
            return result;
        }
        for (String part : raw.split(java.util.regex.Pattern.quote(delimiter))) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
