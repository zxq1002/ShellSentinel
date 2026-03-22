package com.example.shelldetector.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 风险等级枚举 - 定义三个风险级别
 * <p>
 * 等级顺序：SAFE(0) &lt; RISK(1) &lt; DANGER(2)
 * </p>
 *
 * <ul>
 *   <li>SAFE - 安全，无风险</li>
 *   <li>RISK - 风险，中等风险操作</li>
 *   <li>DANGER - 高危，危险操作</li>
 * </ul>
 */
public enum RiskLevel {
    /** 安全 - 无风险 */
    SAFE(0, "安全"),
    /** 风险 - 中等风险操作 */
    RISK(1, "风险"),
    /** 高危 - 危险操作 */
    DANGER(2, "高危");

    private static final Logger logger = LoggerFactory.getLogger(RiskLevel.class);

    /** 默认风险等级，当解析失败时使用 */
    private static final RiskLevel DEFAULT_LEVEL = RISK;

    /** 风险等级数值，用于比较 */
    private final int level;
    /** 风险等级描述 */
    private final String description;

    /**
     * 构造函数
     *
     * @param level 风险等级数值
     * @param description 风险等级描述
     */
    RiskLevel(int level, String description) {
        this.level = level;
        this.description = description;
    }

    /**
     * 获取风险等级数值
     *
     * @return 等级数值
     */
    public int getLevel() {
        return level;
    }

    /**
     * 获取风险等级描述
     *
     * @return 描述字符串
     */
    public String getDescription() {
        return description;
    }

    /**
     * 判断当前风险等级是否大于或等于另一个风险等级
     * <p>
     * 用于与阈值比较，决定是否拦截命令。
     * </p>
     *
     * @param other 要比较的风险等级
     * @return true 表示当前等级 >= other 等级
     */
    public boolean isHigherOrEqualTo(RiskLevel other) {
        return this.level >= other.level;
    }

    /**
     * 健壮的枚举解析方法 - 不区分大小写，支持模糊匹配，解析失败时返回默认值
     *
     * @param value 要解析的字符串
     * @return 解析后的 RiskLevel，解析失败返回 DEFAULT_LEVEL (RISK)
     */
    public static RiskLevel safeValueOf(String value) {
        if (value == null || value.trim().isEmpty()) {
            logger.warn("RiskLevel value is null or empty, using default: {}", DEFAULT_LEVEL);
            return DEFAULT_LEVEL;
        }

        String normalized = value.trim().toUpperCase();

        // 精确匹配
        for (RiskLevel level : values()) {
            if (level.name().equals(normalized)) {
                return level;
            }
        }

        // 模糊匹配（前缀匹配）
        for (RiskLevel level : values()) {
            if (level.name().startsWith(normalized)) {
                logger.warn("RiskLevel '{}' fuzzy matched to '{}'", value, level);
                return level;
            }
        }

        // 解析失败，返回默认值
        logger.warn("Failed to parse RiskLevel '{}', using default: {}", value, DEFAULT_LEVEL);
        return DEFAULT_LEVEL;
    }
}
