package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;
import java.util.List;

/**
 * 简单 Shell 解析器实现
 */
public class SimpleShellParser implements ShellParser {

    private final ShellCommandExtractor extractor;

    public SimpleShellParser() {
        this.extractor = new ShellCommandExtractor();
    }

    public SimpleShellParser(ShellCommandExtractor extractor) {
        this.extractor = extractor;
    }

    @Override
    public List<String> extractCommands(String shellCommand) throws ShellParseException {
        return extractor.extractCommands(shellCommand);
    }
}
