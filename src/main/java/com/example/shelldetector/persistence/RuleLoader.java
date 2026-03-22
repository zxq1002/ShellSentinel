package com.example.shelldetector.persistence;

import com.example.shelldetector.exception.RulePersistenceException;
import com.example.shelldetector.model.Rule;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RuleLoader {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<Rule> loadFromJson(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        try {
            Map<String, Object> data = objectMapper.readValue(file, new TypeReference<Map<String, Object>>() {});
            return extractRules(data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to load rules from " + file, e);
        }
    }

    public static List<Rule> loadFromJson(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        return loadFromJson(new File(path));
    }

    public static List<Rule> loadFromJson(InputStream is) {
        if (is == null) {
            throw new IllegalArgumentException("InputStream cannot be null");
        }
        try {
            Map<String, Object> data = objectMapper.readValue(is, new TypeReference<Map<String, Object>>() {});
            return extractRules(data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to load rules from stream", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Rule> extractRules(Map<String, Object> data) {
        List<Rule> rules = new ArrayList<>();
        List<Map<String, Object>> ruleMaps = (List<Map<String, Object>>) data.get("rules");
        if (ruleMaps != null) {
            for (Map<String, Object> rm : ruleMaps) {
                Rule.Builder builder = Rule.builder()
                        .id((String) rm.get("id"))
                        .name((String) rm.get("name"))
                        .pattern((String) rm.get("pattern"))
                        .description((String) rm.get("description"))
                        .enabled(Boolean.TRUE.equals(rm.get("enabled")));

                String typeStr = (String) rm.get("type");
                if ("WHITELIST".equals(typeStr)) {
                    builder.whitelist();
                } else {
                    builder.blacklist();
                }

                String riskStr = (String) rm.get("riskLevel");
                if (riskStr != null) {
                    builder.riskLevel(com.example.shelldetector.model.RiskLevel.safeValueOf(riskStr));
                }

                rules.add(builder.build());
            }
        }
        return rules;
    }
}
