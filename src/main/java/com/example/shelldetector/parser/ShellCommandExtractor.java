package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Shell 命令提取器 - 将复合命令拆分为子命令
 * <p>
 * 按命令分隔符 [;|&] 分割命令字符串，但会正确处理：
 * <ul>
 *     <li>单引号和双引号内的分隔符（不会被当作分隔符）</li>
 *     <li>转义字符（转义后的分隔符不会被当作分隔符）</li>
 *     <li>保留重定向操作符（>, >>, < 等）在子命令中</li>
 * </ul>
 * 确保后续检测可以看到完整的命令上下文。
 * </p>
 *
 * <p>示例：</p>
 * <pre>{@code
 * "ps -ef | rm -rf xxx.sh"
 *   → ["ps -ef", "rm -rf xxx.sh"]
 *
 * "echo 'Hello; rm -rf /'"
 *   → ["echo 'Hello; rm -rf /'"]  (引号内的分号不分割)
 *
 * "echo \\; rm -rf /"
 *   → ["echo \\; rm -rf /"]  (转义的分号不分割)
 * }</pre>
 */
public class ShellCommandExtractor {

    /**
     * 从复合命令中提取子命令列表
     * <p>
     * 按 [;|&] 分割命令，但会正确处理引号和转义字符，
     * 保留重定向操作符在子命令中，确保每个子命令都包含完整的上下文信息供后续检测。
     * </p>
     *
     * @param shellCommand 完整的 Shell 命令字符串
     * @return 子命令列表，空命令返回空列表
     * @throws ShellParseException 如果解析过程出错
     */
    public List<String> extractCommands(String shellCommand) {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return Collections.emptyList();
        }

        try {
            List<String> commands = new ArrayList<>();
            StringBuilder currentCommand = new StringBuilder();
            boolean inSingleQuote = false;
            boolean inDoubleQuote = false;
            boolean escapeNext = false;

            for (int i = 0; i < shellCommand.length(); i++) {
                char c = shellCommand.charAt(i);

                if (escapeNext) {
                    // 前一个字符是转义符，当前字符直接添加
                    currentCommand.append(c);
                    escapeNext = false;
                    continue;
                }

                if (c == '\\' && !inSingleQuote) {
                    // 转义符，不在单引号内时生效
                    currentCommand.append(c);
                    escapeNext = true;
                    continue;
                }

                if (c == '\'') {
                    // 单引号切换
                    inSingleQuote = !inSingleQuote;
                    currentCommand.append(c);
                    continue;
                }

                if (c == '"' && !inSingleQuote) {
                    // 双引号切换，不在单引号内时生效
                    inDoubleQuote = !inDoubleQuote;
                    currentCommand.append(c);
                    continue;
                }

                // 检查是否是命令分隔符，且不在任何引号内
                if ((c == ';' || c == '|' || c == '&') && !inSingleQuote && !inDoubleQuote) {
                    // 遇到分隔符，完成当前命令
                    addCommandIfNotEmpty(commands, currentCommand);
                    currentCommand.setLength(0);
                } else {
                    // 普通字符，添加到当前命令
                    currentCommand.append(c);
                }
            }

            // 添加最后一个命令
            addCommandIfNotEmpty(commands, currentCommand);

            return commands;
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command: " + shellCommand, e);
        }
    }

    /**
     * 添加命令到列表，如果非空的话
     */
    private void addCommandIfNotEmpty(List<String> commands, StringBuilder commandBuilder) {
        String trimmed = commandBuilder.toString().trim();
        if (!trimmed.isEmpty()) {
            commands.add(trimmed);
        }
    }
}
