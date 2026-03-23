package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.parser.antlr.BashLexer;
import com.example.shelldetector.parser.antlr.BashParser;
import com.example.shelldetector.parser.antlr.BashParserBaseListener;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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
     * 设计说明：
     * <ol>
     *     <li><b>子命令优先提取</b>：对于 `echo $(rm -rf /)`，会同时提取 "rm -rf /" 和 "echo $()"
     *         <ul>
     *             <li>核心目标：确保危险命令 "rm -rf /" 一定被提取</li>
     *             <li>次要考虑：父命令可能不完整（仅显示 "echo $()"），但不影响安全检测</li>
     *             <li>双重保险：DetectionEngine 会对原始整串再做一次黑名单扫描</li>
     *         </ul>
     *     </li>
     *     <li><b>自动去重</b>：使用 LinkedHashSet 去除重复命令</li>
     *     <li><b>递归保护</b>：限制最大嵌套深度 50，防止 StackOverflowError</li>
     * </ol>
     * </p>
     */
    private static class CommandExtractorListener extends BashParserBaseListener {

        private static final int MAX_RECURSION_DEPTH = 50;

        private final List<String> commands = new ArrayList<>();
        private final java.util.Stack<StringBuilder> commandStack = new java.util.Stack<>();
        private int recursionDepth = 0;
        private int lastTokenType = -1;
        private String lastTokenText = "";

        @Override
        public void enterSimpleCommand(BashParser.SimpleCommandContext ctx) {
            if (recursionDepth >= MAX_RECURSION_DEPTH) {
                throw new ShellParseException("Recursion depth limit exceeded: " + MAX_RECURSION_DEPTH);
            }
            recursionDepth++;
            commandStack.push(new StringBuilder());
            lastTokenType = -1;
            lastTokenText = "";
        }

        @Override
        public void exitSimpleCommand(BashParser.SimpleCommandContext ctx) {
            recursionDepth--;
            StringBuilder current = commandStack.pop();
            String cmd = current.toString().trim();
            if (!cmd.isEmpty()) {
                commands.add(cmd);
            }
            // 注意：不将子命令追加到父级命令中，避免重复提取
            // 每个 simpleCommand 都会独立添加到 commands 列表
        }

        @Override
        public void visitTerminal(org.antlr.v4.runtime.tree.TerminalNode node) {
            if (commandStack.isEmpty()) {
                return;
            }

            int tokenType = node.getSymbol().getType();
            String text = node.getText();

            StringBuilder currentCommand = commandStack.peek();

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

            // 操作符类 token 之间不需要空格：2>&1, >>, >&, ${, $(, ))
            if (isOperatorToken(prevType) && isOperatorToken(currType)) {
                return false;
            }

            // 特殊处理变量扩张和子 shell：${VAR}, $(CMD)
            // 1. DOLLAR 后面接任何操作符或单词都不需要空格
            if (prevType == BashLexer.DOLLAR) {
                return false;
            }
            // 2. 左括号/左花括号后面不需要空格
            if (prevType == BashLexer.LPAREN || prevType == BashLexer.LBRACE) {
                return false;
            }
            // 3. 右括号/右花括号前面不需要空格
            if (currType == BashLexer.RPAREN || currType == BashLexer.RBRACE) {
                return false;
            }

            // 只有重定向符后接文件名（WORD）不需要空格：>file, >>file
            if (isRedirectionToken(prevType) && currType == BashLexer.WORD) {
                return false;
            }

            // 数字（WORD 类型但内容全是数字）后接重定向操作符不需要空格：2>, 1>
            if (prevType == BashLexer.WORD && isAllDigits(prevText) && isRedirectionToken(currType)) {
                return false;
            }

            // 默认需要空格
            return true;
        }

        /**
         * 判断是否为重定向操作符
         */
        private boolean isRedirectionToken(int tokenType) {
            return tokenType == BashLexer.REDIRECT_OUT
                    || tokenType == BashLexer.REDIRECT_APPEND
                    || tokenType == BashLexer.REDIRECT_IN
                    || tokenType == BashLexer.REDIRECT_OUT_AND_ERR
                    || tokenType == BashLexer.REDIRECT_APPEND_ALL
                    || tokenType == BashLexer.REDIRECT_OUT_FD
                    || tokenType == BashLexer.REDIRECT_IN_FD;
        }

        /**
         * 判断是否为操作符类 token
         */
        private boolean isOperatorToken(int tokenType) {
            return isRedirectionToken(tokenType)
                    || tokenType == BashLexer.AMPERSAND
                    || tokenType == BashLexer.PIPE
                    || tokenType == BashLexer.LPAREN
                    || tokenType == BashLexer.RPAREN
                    || tokenType == BashLexer.LBRACE
                    || tokenType == BashLexer.RBRACE
                    || tokenType == BashLexer.DOLLAR
                    || tokenType == BashLexer.BACKTICK;
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
            // 使用 LinkedHashSet 去重，保持顺序
            Set<String> uniqueCommands = new LinkedHashSet<>(commands);
            return new ArrayList<>(uniqueCommands);
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
