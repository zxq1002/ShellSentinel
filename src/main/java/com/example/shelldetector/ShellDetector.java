package com.example.shelldetector;

import com.example.shelldetector.builtin.BuiltinRules;
import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.core.DetectionEngine;
import com.example.shelldetector.core.RuleConflictChecker;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;
import com.example.shelldetector.persistence.RuleSaver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shell 命令检测器 - 提供友好的 Fluent Builder API
 * <p>
 * 这是库的主要入口类，封装了检测引擎和规则管理功能。
 * 支持动态添加/删除/更新规则，并可将规则持久化到 JSON 文件。
 * </p>
 *
 * <p>使用示例：</p>
 * <pre>{@code
 * // 使用默认配置和内置规则
 * ShellDetector detector = ShellDetector.createDefault();
 * DetectionResult result = detector.detect("rm -rf /");
 *
 * // 自定义配置
 * ShellDetector detector = ShellDetector.builder()
 *     .withDefaultRules()
 *     .withThreshold(RiskLevel.DANGER)
 *     .withRulesFromJson("my-rules.json")
 *     .build();
 * }</pre>
 */
public class ShellDetector {
    private final DetectionConfig config;
    private final DetectionEngine engine;
    private final Map<String, Rule> rules;

    /**
     * 私有构造函数，通过 Builder 创建实例
     *
     * @param builder Builder 对象
     */
    private ShellDetector(Builder builder) {
        this.config = builder.config;
        this.engine = new DetectionEngine(config);
        this.rules = new ConcurrentHashMap<>();
        for (Rule rule : builder.rules) {
            this.rules.put(rule.getId(), rule);
        }
    }

    /**
     * 检测命令是否安全
     *
     * @param command 待检测的命令字符串
     * @return 检测结果，包含是否通过、匹配的规则、风险等级等信息
     */
    public DetectionResult detect(String command) {
        return engine.detect(command, new ArrayList<>(rules.values()));
    }

    /**
     * 添加新规则
     * <p>
     * 如果规则ID已存在，会覆盖原有规则。
     * </p>
     *
     * @param rule 要添加的规则
     * @throws IllegalArgumentException 如果 rule 或 rule.id 为 null
     */
    public void addRule(Rule rule) {
        if (rule == null || rule.getId() == null) {
            throw new IllegalArgumentException("Rule and rule id cannot be null");
        }
        rules.put(rule.getId(), rule);
    }

    /**
     * 删除规则
     *
     * @param ruleId 要删除的规则ID
     */
    public void removeRule(String ruleId) {
        if (ruleId != null) {
            rules.remove(ruleId);
        }
    }

    /**
     * 更新规则
     * <p>
     * 与 addRule 行为相同，提供此方法是为了 API 语义清晰。
     * </p>
     *
     * @param rule 要更新的规则
     * @throws IllegalArgumentException 如果 rule 或 rule.id 为 null
     */
    public void updateRule(Rule rule) {
        if (rule == null || rule.getId() == null) {
            throw new IllegalArgumentException("Rule and rule id cannot be null");
        }
        rules.put(rule.getId(), rule);
    }

    /**
     * 获取指定ID的规则
     *
     * @param ruleId 规则ID
     * @return 规则对象，不存在时返回 null
     */
    public Rule getRule(String ruleId) {
        if (ruleId == null) {
            return null;
        }
        return rules.get(ruleId);
    }

    /**
     * 获取所有规则的列表
     *
     * @return 规则列表的副本（不可修改原列表）
     */
    public List<Rule> getRules() {
        return new ArrayList<>(rules.values());
    }

    /**
     * 将当前规则保存到 JSON 文件
     *
     * @param path 文件路径
     * @throws IllegalArgumentException 如果 path 为 null 或空
     */
    public void saveRulesToJson(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        RuleSaver.saveToJson(getRules(), path);
    }

    /**
     * 将当前规则保存到 JSON 文件
     *
     * @param file 文件对象
     * @throws IllegalArgumentException 如果 file 为 null
     */
    public void saveRulesToJson(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        RuleSaver.saveToJson(getRules(), file);
    }

    /**
     * 创建使用默认配置和内置规则的检测器
     *
     * @return 默认配置的 ShellDetector 实例
     */
    public static ShellDetector createDefault() {
        return builder().withDefaultRules().build();
    }

    /**
     * 创建 Builder 对象
     *
     * @return Builder 实例
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent Builder - 用于构建 ShellDetector 实例
     */
    public static class Builder {
        private static final Logger logger = LoggerFactory.getLogger(Builder.class);
        private DetectionConfig config = DetectionConfig.builder().build();
        private List<Rule> rules = new ArrayList<>();
        private boolean failOnRuleConflict = false;

        /**
         * 设置检测配置
         *
         * @param config 检测配置对象
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 config 为 null
         */
        public Builder withConfig(DetectionConfig config) {
            if (config == null) {
                throw new IllegalArgumentException("Config cannot be null");
            }
            this.config = config;
            return this;
        }

        /**
         * 设置风险阈值
         *
         * @param threshold 风险阈值
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 threshold 为 null
         */
        public Builder withThreshold(RiskLevel threshold) {
            if (threshold == null) {
                throw new IllegalArgumentException("Threshold cannot be null");
            }
            // 保持现有配置，只修改 threshold 属性
            this.config = DetectionConfig.builder()
                    .threshold(threshold)
                    .failOnParseError(this.config.isFailOnParseError())
                    .build();
            return this;
        }

        /**
         * 添加内置规则
         *
         * @return Builder 实例
         */
        public Builder withDefaultRules() {
            this.rules.addAll(BuiltinRules.getRules());
            return this;
        }

        /**
         * 添加多条规则
         *
         * @param rules 规则列表
         * @return Builder 实例
         */
        public Builder withRules(List<Rule> rules) {
            if (rules != null) {
                this.rules.addAll(rules);
            }
            return this;
        }

        /**
         * 添加单条规则
         *
         * @param rule 规则对象
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 rule 为 null
         */
        public Builder withRule(Rule rule) {
            if (rule == null) {
                throw new IllegalArgumentException("Rule cannot be null");
            }
            this.rules.add(rule);
            return this;
        }

        /**
         * 从 JSON 文件加载规则
         *
         * @param path 文件路径
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 path 为 null 或空
         */
        public Builder withRulesFromJson(String path) {
            if (path == null || path.trim().isEmpty()) {
                throw new IllegalArgumentException("Path cannot be null or empty");
            }
            this.rules.addAll(RuleLoader.loadFromJson(path));
            return this;
        }

        /**
         * 从 JSON 文件加载规则
         *
         * @param file 文件对象
         * @return Builder 实例
         * @throws IllegalArgumentException 如果 file 为 null
         */
        public Builder withRulesFromJson(File file) {
            if (file == null) {
                throw new IllegalArgumentException("File cannot be null");
            }
            this.rules.addAll(RuleLoader.loadFromJson(file));
            return this;
        }

        /**
         * 设置规则冲突时是否失败
         *
         * @param failOnConflict true 表示规则冲突时抛出异常，false 表示仅记录警告
         * @return Builder 实例
         */
        public Builder failOnRuleConflict(boolean failOnConflict) {
            this.failOnRuleConflict = failOnConflict;
            return this;
        }

        /**
         * 构建 ShellDetector 实例
         *
         * @return ShellDetector 实例
         * @throws IllegalStateException 如果 failOnRuleConflict=true 且存在规则冲突
         */
        public ShellDetector build() {
            // 检测规则冲突
            RuleConflictChecker conflictChecker = new RuleConflictChecker();
            List<RuleConflictChecker.Conflict> conflicts = conflictChecker.checkConflicts(rules);

            if (!conflicts.isEmpty()) {
                StringBuilder message = new StringBuilder();
                message.append("Found ").append(conflicts.size()).append(" rule conflict(s):\n");
                for (RuleConflictChecker.Conflict conflict : conflicts) {
                    message.append("  - ").append(conflict).append("\n");
                }
                String conflictMessage = message.toString();

                if (failOnRuleConflict) {
                    throw new IllegalStateException(conflictMessage);
                } else {
                    logger.warn(conflictMessage);
                }
            }

            return new ShellDetector(this);
        }
    }
}
