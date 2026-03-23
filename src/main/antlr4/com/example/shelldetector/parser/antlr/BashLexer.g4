lexer grammar BashLexer;

// 基础跳过规则
WHITESPACE: [ \t]+ -> skip;
NEWLINE: '\r'? '\n';

// 复合操作符（高优先级）
ANDAND: '&&';
OROR: '||';
REDIRECT_APPEND: '>>';
REDIRECT_OUT_AND_ERR: '&>';
REDIRECT_APPEND_ALL: '&>>';
REDIRECT_OUT_FD: '>&';
REDIRECT_IN_FD: '<&';

// 单字符操作符
PIPE: '|';
SEMICOLON: ';';
AMPERSAND: '&';
LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';
DOLLAR: '$';
BACKTICK: '`';
REDIRECT_OUT: '>';
REDIRECT_IN: '<';
SINGLE_QUOTE: '\'';
DOUBLE_QUOTE: '"';

// 字符串
STRING_SINGLE: '\'' (~['\\] | ESCAPED_CHAR)* '\'';
STRING_DOUBLE: '"' ( ~["\\] | ESCAPED_CHAR )* '"';

// 单词：排除所有操作符字符
// 允许转义字符
WORD: ( ~[ \t\n\r(){}|&;<>$`'"\\] | ESCAPED_CHAR )+;
fragment ESCAPED_CHAR: '\\' .;
