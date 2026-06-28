#!/usr/bin/env bash
#
# 架构红线守护
# ============
# ShellSentinel 是纯校验组件：它只返回重建后的规范串，绝不执行命令。
# 命令的实际执行由调用方负责，且调用方必须执行 ExecGuard 返回的规范串，
# 绝不能把调用方原始输入串回灌给 `sh -c`。
#
# 为防止未来回归（有人在库内新增执行代码、把原始串交给 shell），本检查确保
# 库主代码中不出现任何进程执行 API。任何命中即判违规。
#
set -euo pipefail

SCAN_DIR="${1:-src/main/java}"

# 进程执行相关 API（本库不应出现）
PATTERN='Runtime[[:space:]]*\.[[:space:]]*getRuntime|Runtime[[:space:]]*\.[[:space:]]*exec|new[[:space:]]+ProcessBuilder|ProcessBuilder[[:space:]]*\('

if grep -rnE "$PATTERN" "$SCAN_DIR" 2>/dev/null; then
    echo "" >&2
    echo "RED LINE VIOLATION: 在 $SCAN_DIR 中发现进程执行 API。" >&2
    echo "本库必须保持纯校验，绝不执行命令；执行规范串是调用方的职责。" >&2
    exit 1
fi

echo "OK: $SCAN_DIR 中未发现进程执行 API，架构红线成立。"
