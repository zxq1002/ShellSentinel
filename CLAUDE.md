# ShellSentinel 项目说明

面向容器云平台 exec 接口（底层 `sh -c "<字符串>"`，K8s exec）的**命令安全网关**。default-deny 白名单模型：解析 → 校验 → 用 token 重建**逐参数转义的规范串**再执行；旧黑名单检测引擎已移除。代码在 `com.example.shelldetector.gate`。

## 支持的三大场景

| # | 场景 | 放行方式 | 配置键 |
|---|------|----------|--------|
| ① | 只读查询验证 | 命令名白名单 + 参数策略（`ArgPolicy`）+ 纯管道（如 `ps -ef \| grep x`） | 内置（代码固化） |
| ② | 执行镜像内可信脚本 | `sh <受信脚本路径> [args]`，路径精确或 `前缀-*.sh` 匹配；sh 所有开关禁止 | `gate.sh.scripts` |
| ③ | 混沌故障注入 | 整条命令白名单：精确整行 或 类型占位符模板（`{int}`/`{int:MIN..MAX}`/`{enum:A\|B\|C}`） | `gate.exact.commands`、`gate.command.templates` |

三类通道独立、并列叠加；未命中任一通道一律 `COMMAND_NOT_ALLOWED`。

## 不可违背的约束（红线）

- **执行规范串，绝不回灌原始串给 `sh -c`**；本库自身不执行命令（`scripts/check-redline.sh` 在 CI 守护，库内禁 `Runtime.exec`/`ProcessBuilder`）。
- **安全关键的命令白名单与参数策略固化在受评审代码**；仅部署相关的脚本前缀与混沌命令走外部配置（`GateConfig`）。不要把 `sh`/`rm` 等加进只读白名单。
- 危险命令（场景③）只能按**整条命令**登记，**绝不按命令名**放行。

## 入口与构建

- 门面：`ExecGuard`（`canonicalOrThrow` / `inspect`）；网关：`CommandGate.builder()...build()` 或 `GateConfig.fromFile(...)`；审计：`AuditSink` / `Slf4jAuditSink`。
- 改动走 TDD（红→绿）；`mvn test` + `./scripts/check-redline.sh` 全绿后提交。在 `main` 上开发先建分支。
- 详细设计与动因见 `README.md`。
