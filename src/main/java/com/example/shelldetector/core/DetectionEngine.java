package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.parser.ShellCommandExtractor;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 检测引擎 - 核心检测逻辑实现
 * <p>
 * 检测流程：
 * <ol>
 *     <li>命令提取 - 按 [;|&] 分割命令字符串</li>
 *     <li>整条命令白名单检查 - 完全根据白名单规则校验</li>
 *     <li>所有子命令白名单检查 - 检查每个子命令是否都在白名单中</li>
 *     <li>黑名单检测 - 先对原始整串检测，再逐个检测子命令（捕获分隔符）</li>
 *     <li>风险评估 - 确定最高风险等级并与阈值比较</li>
 * </ol>
 * </p>
 */
public class DetectionEngine {
    private final DetectionConfig config;
    private final RuleMatcher ruleMatcher;
    private final RiskEvaluator riskEvaluator;
    private final ShellCommandExtractor commandExtractor;

    /**
     * 构造检测引擎
     *
     * @param config 检测配置
     */
    public DetectionEngine(DetectionConfig config) {
        this.config = config;
        this.ruleMatcher = new RuleMatcher();
        this.riskEvaluator = new RiskEvaluator();
        this.commandExtractor = new ShellCommandExtractor();
    }

    /**
     * 检测命令是否安全
     * <p>
     * 执行完整的检测流程，任一阶段通过则直接返回结果。
     * </p>
     *
     * @param entireCommand 完整的命令字符串
     * @param rules 规则列表
     * @return 检测结果
     */
    public DetectionResult detect(String entireCommand, List<Rule> rules) {
        DetectionResult.Builder resultBuilder = DetectionResult.builder();

        // 空命令直接通过
        if (entireCommand == null) {
            return resultBuilder.passed(true).build();
        }

        // 规则为空时初始化为空列表
        if (rules == null) {
            rules = new ArrayList<>();
        }

        try {
            // 步骤1：提取子命令
            List<String> commands = commandExtractor.extractCommands(entireCommand);

            // 没有提取到命令，直接通过
            if (commands.isEmpty()) {
                return resultBuilder.passed(true).build();
            }

            // 步骤2：检查整条命令是否匹配白名单
            if (ruleMatcher.isEntireCommandWhitelisted(entireCommand, rules)) {
                return resultBuilder.passed(true).build();
            }

            // 步骤3：检查所有子命令是否都匹配白名单
            if (ruleMatcher.areAllCommandsWhitelisted(commands, rules)) {
                return resultBuilder.passed(true).build();
            }

            // 步骤4：检测黑名单规则
            Set<Rule> uniqueMatchedRules = new LinkedHashSet<>();

            // 【新增】：针对原始完整命令进行一次黑名单全量扫描
            // 目的：捕获在拆分过程中丢失的管道符 | 、分号 ; 、后台符 & 等符号
            List<Rule> entireCommandMatches = ruleMatcher.matchBlacklist(entireCommand, rules);
            uniqueMatchedRules.addAll(entireCommandMatches);

            // 【原有】：针对拆分后的具体子命令进行扫描
            for (String cmd : commands) {
                List<Rule> matched = ruleMatcher.matchBlacklist(cmd, rules);
                uniqueMatchedRules.addAll(matched);
            }

            // 统一添加到 resultBuilder（去重后）
            List<Rule> allMatchedRules = new ArrayList<>(uniqueMatchedRules);
            for (Rule rule : allMatchedRules) {
                resultBuilder.addMatchedRule(rule);
            }

            // 步骤5：风险评估
            RiskLevel highestRisk = riskEvaluator.evaluateHighestRisk(allMatchedRules);
            boolean shouldBlock = riskEvaluator.shouldBlock(highestRisk, config.getThreshold());

            // 超过阈值则拦截
            if (shouldBlock) {
                resultBuilder.passed(false)
                        .highestRiskLevel(highestRisk)
                        .blockReason("Command exceeded risk threshold: " + highestRisk.getDescription());
            }

        } catch (ShellParseException e) {
            // 解析失败时根据配置决定是否抛出异常
            if (config.isFailOnParseError()) {
                throw e;
            }
            // 安全策略：无法解析的命令应视为高风险，默认拦截
            // "无法解析"通常意味着恶意混淆或复杂语法
            resultBuilder.passed(false)
                    .highestRiskLevel(RiskLevel.DANGER)
                    .blockReason("Command parse failed, treated as potential risk: " + e.getMessage());
        }

        return resultBuilder.build();
    }
}
