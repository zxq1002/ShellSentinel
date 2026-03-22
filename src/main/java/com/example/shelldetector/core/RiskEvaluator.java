package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;

import java.util.List;

/**
 * 风险评估器 - 评估匹配规则的风险等级
 * <p>
 * 负责从匹配的规则中确定最高风险等级，并与阈值比较决定是否拦截。
 * </p>
 */
public class RiskEvaluator {

    /**
     * 评估匹配规则的最高风险等级
     * <p>
     * 遍历所有匹配的规则，找出其中风险等级最高的一个。
     * 风险等级顺序：SAFE(0) &lt; RISK(1) &lt; DANGER(2)
     * </p>
     *
     * @param matchedRules 匹配成功的规则列表
     * @return 最高风险等级，无匹配规则时返回 SAFE
     */
    public RiskLevel evaluateHighestRisk(List<Rule> matchedRules) {
        RiskLevel highest = RiskLevel.SAFE;
        if (matchedRules == null) {
            return highest;
        }
        for (Rule rule : matchedRules) {
            if (rule != null && rule.getRiskLevel() != null && rule.getRiskLevel().isHigherOrEqualTo(highest)) {
                highest = rule.getRiskLevel();
            }
        }
        return highest;
    }

    /**
     * 判断是否应该拦截命令
     * <p>
     * 当风险等级大于或等于阈值时，应该拦截命令。
     * 特例：SAFE 级别即使等于 SAFE 阈值也不拦截，因为 SAFE 表示完全安全。
     * </p>
     *
     * @param riskLevel 评估出的风险等级
     * @param threshold 配置的风险阈值
     * @return true 表示应该拦截，false 表示可以通过
     */
    public boolean shouldBlock(RiskLevel riskLevel, RiskLevel threshold) {
        if (riskLevel == null || threshold == null) {
            return false;
        }
        // 特例：SAFE 级别永远不拦截
        if (riskLevel == RiskLevel.SAFE) {
            return false;
        }
        return riskLevel.isHigherOrEqualTo(threshold);
    }
}
