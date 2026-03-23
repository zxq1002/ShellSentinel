parser grammar BashParser;
options { tokenVocab=BashLexer; }

parse: commandList EOF;

commandList: command ( (SEMICOLON | NEWLINE) command )* (SEMICOLON | NEWLINE)?;

command: pipeline ( (ANDAND | OROR) pipeline )*;

pipeline: simpleCommand (PIPE simpleCommand)*;

// 核心改进：允许重定向和单词任意穿插
simpleCommand: (element | redirection)+;

element: word;

// 重定向规则：支持可选的数字前缀（文件描述符）
redirection: WORD? (REDIRECT_OUT | REDIRECT_APPEND | REDIRECT_IN | REDIRECT_OUT_AND_ERR | REDIRECT_APPEND_ALL | REDIRECT_OUT_FD | REDIRECT_IN_FD) word;

// 支持命令替换和其他 shell 结构
word: (WORD | STRING_SINGLE | STRING_DOUBLE)
    | variableExpansion
    | subshell
    ;

subshell: DOLLAR LPAREN commandList RPAREN
        | BACKTICK commandList BACKTICK
        ;

variableExpansion: DOLLAR (WORD | LBRACE WORD RBRACE);
