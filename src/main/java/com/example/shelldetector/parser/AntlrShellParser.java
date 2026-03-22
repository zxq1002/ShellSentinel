package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.parser.antlr.BashLexer;
import com.example.shelldetector.parser.antlr.BashParser;
import com.example.shelldetector.parser.antlr.BashParserBaseListener;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.ArrayList;
import java.util.List;

/**
 * 基于 ANTLR 的 Shell 解析器实现
 * <p>
 * 使用 ANTLR Bash 语法进行解析，能够更准确地处理复杂的 Shell 语法。
 * </p>
 */
public class AntlrShellParser implements ShellParser {

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> extractCommands(String shellCommand) throws ShellParseException {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return new ArrayList<>();
        }

        try {
            ANTLRInputStream input = new ANTLRInputStream(shellCommand);
            BashLexer lexer = new BashLexer(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            BashParser parser = new BashParser(tokens);

            // 移除默认错误监听器，添加我们自己的（让语法错误抛出异常）
            lexer.removeErrorListeners();
            parser.removeErrorListeners();
            lexer.addErrorListener(new ThrowingErrorListener());
            parser.addErrorListener(new ThrowingErrorListener());

            CommandExtractorListener listener = new CommandExtractorListener();
            ParseTreeWalker walker = new ParseTreeWalker();
            walker.walk(listener, parser.parse());

            return listener.getCommands();
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command with ANTLR: " + shellCommand, e);
        }
    }

    /**
     * ANTLR 解析监听器，用于从 AST 中提取命令
     * <p>
     * 改进点：智能空格处理，避免 2>&1 变成 2 > & 1
     * </p>
     */
    private static class CommandExtractorListener extends BashParserBaseListener {

        private final List<String> commands = new ArrayList<>();
        private final StringBuilder currentCommand = new StringBuilder();
        private boolean inSimpleCommand = false;
        private int lastTokenType = -1;
        private String lastTokenText = "";

        @Override
        public void enterSimpleCommand(BashParser.SimpleCommandContext ctx) {
            inSimpleCommand = true;
            currentCommand.setLength(0);
            lastTokenType = -1;
            lastTokenText = "";
        }

        @Override
        public void exitSimpleCommand(BashParser.SimpleCommandContext ctx) {
            inSimpleCommand = false;
            String cmd = currentCommand.toString().trim();
            if (!cmd.isEmpty()) {
                commands.add(cmd);
            }
            currentCommand.setLength(0);
        }

        @Override
        public void visitTerminal(org.antlr.v4.runtime.tree.TerminalNode node) {
            if (!inSimpleCommand) {
                return;
            }

            int tokenType = node.getSymbol().getType();
            String text = node.getText();

            // 智能判断是否需要添加空格
            if (currentCommand.length() > 0 && needsSpace(lastTokenType, lastTokenText, tokenType, text)) {
                currentCommand.append(" ");
            }

            currentCommand.append(text);
            lastTokenType = tokenType;
            lastTokenText = text;
        }

        /**
         * 智能判断两个 token 之间是否需要添加空格
         */
        private boolean needsSpace(int prevType, String prevText, int currType, String currText) {
            if (prevType == -1) {
                return false;
            }

            // 操作符类 token 之间不需要空格：2>&1, >>, >&, 1>/dev/null
            if (isOperatorToken(prevType) && isOperatorToken(currType)) {
                return false;
            }

            // 数字（WORD 类型但内容全是数字）后接操作符不需要空格
            if (prevType == BashLexer.WORD && isAllDigits(prevText) && isOperatorToken(currType)) {
                return false;
            }

            // 默认需要空格
            return true;
        }

        /**
         * 判断是否为操作符类 token
         */
        private boolean isOperatorToken(int tokenType) {
            return tokenType == BashLexer.REDIRECT_OUT
                    || tokenType == BashLexer.REDIRECT_APPEND
                    || tokenType == BashLexer.REDIRECT_IN
                    || tokenType == BashLexer.AMPERSAND
                    || tokenType == BashLexer.PIPE
                    || tokenType == BashLexer.LPAREN
                    || tokenType == BashLexer.RPAREN;
        }

        /**
         * 判断字符串是否全是数字
         */
        private boolean isAllDigits(String text) {
            if (text == null || text.isEmpty()) {
                return false;
            }
            for (char c : text.toCharArray()) {
                if (!Character.isDigit(c)) {
                    return false;
                }
            }
            return true;
        }

        List<String> getCommands() {
            return new ArrayList<>(commands);
        }
    }

    /**
     * 错误监听器，将 ANTLR 错误转换为异常
     */
    private static class ThrowingErrorListener extends org.antlr.v4.runtime.BaseErrorListener {
        @Override
        public void syntaxError(org.antlr.v4.runtime.Recognizer<?, ?> recognizer,
                               Object offendingSymbol,
                               int line,
                               int charPositionInLine,
                               String msg,
                               org.antlr.v4.runtime.RecognitionException e) {
            throw new ShellParseException("Syntax error at line " + line + ":" + charPositionInLine + " - " + msg, e);
        }
    }
}
