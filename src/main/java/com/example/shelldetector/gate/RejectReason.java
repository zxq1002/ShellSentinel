package com.example.shelldetector.gate;

/**
 * 命令网关拒绝原因。
 */
public enum RejectReason {
    /** 输入为空 */
    EMPTY,
    /** 超过长度上限 */
    TOO_LONG,
    /** 解析失败（如引号未闭合） */
    PARSE_FAILED,
    /** 含被禁止的 shell 语法（分隔符、逻辑符、重定向、命令替换、进程替换等） */
    FORBIDDEN_SYNTAX,
    /** 命令名不在白名单内 */
    COMMAND_NOT_ALLOWED,
    /** 参数不被该命令的参数策略允许 */
    ARG_NOT_ALLOWED
}
