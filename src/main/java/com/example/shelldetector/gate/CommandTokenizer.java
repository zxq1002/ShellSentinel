package com.example.shelldetector.gate;

import java.util.ArrayList;
import java.util.List;

/**
 * 受信配置命令行的 quote-aware 分词器。
 * <p>
 * 用于把<b>配置</b>里的混沌精确命令与模板行拆成 token，规则与 {@link CommandGate} 识别器对
 * <b>输入</b>的处理保持一致（识别单/双引号、去掉引号、只按未被引号包裹的 ASCII 空格/制表符
 * 分词——不用 {@code Character.isWhitespace}，避免把 {@code CommandGate} 不识别为分隔符的
 * 其它空白字符错当分隔符），从而保证「配置 token」与「输入 token」可正确比对。
 * </p>
 * <p>
 * 注意：这是<b>受信配置</b>专用，不强制 {@code FORBIDDEN_BARE}、不处理管道，因此模板里的
 * {@code {int}} 等占位符（含 {@code { } |} 等字符）会原样保留在 token 内。
 * </p>
 */
final class CommandTokenizer {

    private CommandTokenizer() {
    }

    /**
     * 将一行命令拆成 token（去引号、按未引用空白分词）。
     *
     * @throws IllegalArgumentException 引号未闭合（装配期 fail-fast，见类注释）
     */
    static List<String> tokenize(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder token = new StringBuilder();
        boolean started = false;
        boolean inSingle = false;
        boolean inDouble = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inSingle) {
                if (c == '\'') {
                    inSingle = false;
                } else {
                    token.append(c);
                }
                continue;
            }
            if (inDouble) {
                if (c == '"') {
                    inDouble = false;
                } else {
                    token.append(c);
                }
                continue;
            }
            if (c == '\'') {
                inSingle = true;
                started = true;
            } else if (c == '"') {
                inDouble = true;
                started = true;
            } else if (c == ' ' || c == '\t') {
                if (started) {
                    tokens.add(token.toString());
                    token.setLength(0);
                    started = false;
                }
            } else {
                token.append(c);
                started = true;
            }
        }
        if (inSingle || inDouble) {
            // 未闭合引号会让后续内容（含本应作为分隔符的空白）被静默吞入同一个 token，
            // 产出一条运维没料到的死配置/错配置——与 ScriptPattern.of 拒绝 '..' 段同一
            // 防御哲学：宁可装配期直接报错，也不悄悄加载成行为诡异的配置
            throw new IllegalArgumentException("配置命令行含未闭合引号: " + line);
        }
        if (started) {
            tokens.add(token.toString());
        }
        return tokens;
    }
}
