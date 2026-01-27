/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
 * For details, please see https://owasp.org/www-project-benchmark/.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Bahar Shah
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.Reader;

/**
 * Reader for SARIF produced by the Datadog SAIST experiment tool:
 * https://github.com/DataDog/datadog-saist-experiment
 */
public class DatadogSaistReader extends Reader {
    private static final String DATADOG_SAIST_TOOL_NAME = "datadog-ai-static-analyzer";

    /** Enumeration of CWE + category IDs for SAIST rules. */
    private enum Type {
        COMMAND_INJECTION(77),      // CWE-77
        SQL_INJECTION(89),          // CWE-89
        XPATH_INJECTION(91),        // CWE-91
        XSS(79),                    // CWE-79
        LDAP_INJECTION(90),         // CWE-90
        PATH_TRAVERSAL(22),         // CWE-22
        TRUST_BOUNDARY(501),        // CWE-501
        WEAK_HASH(328),             // CWE-328
        INSECURE_COOKIE(614),       // CWE-614
        BROKEN_CRYPTO(327),         // CWE-327
        ACCESS_CONTROL(284),        // CWE-284
        CODE_INJECTION(94),         // CWE-94
        DESERIALIZATION(502);       // CWE-502

        private final int number;
        private final String id;

        Type(final int number) {
            this.number = number;
            this.id = "saist-" + name().toLowerCase().replaceAll("_", "-");
        }
    }

    /** Static mapping of all SAIST rule IDs to their corresponding Type. */
    private static final Map<String, Type> RULE_ID_TO_TYPE = new HashMap<>();
    static {
        // Java rules
        RULE_ID_TO_TYPE.put("datadog/java-cmdi", Type.COMMAND_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/java-sqli", Type.SQL_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/java-xpathi", Type.XPATH_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/java-xss", Type.XSS);
        RULE_ID_TO_TYPE.put("datadog/java-ldapi", Type.LDAP_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/java-pathtraversal", Type.PATH_TRAVERSAL);
        RULE_ID_TO_TYPE.put("datadog/java-trustboundary", Type.TRUST_BOUNDARY);
        RULE_ID_TO_TYPE.put("datadog/java-weakhash", Type.WEAK_HASH);
        RULE_ID_TO_TYPE.put("datadog/java-insecurecookie", Type.INSECURE_COOKIE);
        RULE_ID_TO_TYPE.put("datadog/java-brokencrypto", Type.BROKEN_CRYPTO);
        RULE_ID_TO_TYPE.put("datadog/java-accesscontrol", Type.ACCESS_CONTROL);
        RULE_ID_TO_TYPE.put("datadog/java-codei", Type.CODE_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/java-deserialization", Type.DESERIALIZATION);

        // Go rules
        RULE_ID_TO_TYPE.put("datadog/go-cmdi", Type.COMMAND_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/go-sqli", Type.SQL_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/go-xpathi", Type.XPATH_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/go-xss", Type.XSS);
        RULE_ID_TO_TYPE.put("datadog/go-ldapi", Type.LDAP_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/go-pathtraversal", Type.PATH_TRAVERSAL);
        RULE_ID_TO_TYPE.put("datadog/go-trustboundary", Type.TRUST_BOUNDARY);
        RULE_ID_TO_TYPE.put("datadog/go-weakhash", Type.WEAK_HASH);
        RULE_ID_TO_TYPE.put("datadog/go-insecurecookie", Type.INSECURE_COOKIE);
        RULE_ID_TO_TYPE.put("datadog/go-brokencrypto", Type.BROKEN_CRYPTO);
        RULE_ID_TO_TYPE.put("datadog/go-accesscontrol", Type.ACCESS_CONTROL);
        RULE_ID_TO_TYPE.put("datadog/go-codei", Type.CODE_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/go-deserialization", Type.DESERIALIZATION);

        // Python rules
        RULE_ID_TO_TYPE.put("datadog/python-cmdi", Type.COMMAND_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/python-sqli", Type.SQL_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/python-xpathi", Type.XPATH_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/python-xss", Type.XSS);
        RULE_ID_TO_TYPE.put("datadog/python-ldapi", Type.LDAP_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/python-pathtraversal", Type.PATH_TRAVERSAL);
        RULE_ID_TO_TYPE.put("datadog/python-trustboundary", Type.TRUST_BOUNDARY);
        RULE_ID_TO_TYPE.put("datadog/python-weakhash", Type.WEAK_HASH);
        RULE_ID_TO_TYPE.put("datadog/python-insecurecookie", Type.INSECURE_COOKIE);
        RULE_ID_TO_TYPE.put("datadog/python-brokencrypto", Type.BROKEN_CRYPTO);
        RULE_ID_TO_TYPE.put("datadog/python-accesscontrol", Type.ACCESS_CONTROL);
        RULE_ID_TO_TYPE.put("datadog/python-codei", Type.CODE_INJECTION);
        RULE_ID_TO_TYPE.put("datadog/python-deserialization", Type.DESERIALIZATION);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            if (!resultFile.filename().endsWith(".sarif") || !resultFile.isJson()) {
                return false;
            }

            JSONObject driver = resultFile.json()
                    .getJSONArray("runs").getJSONObject(0)
                    .getJSONObject("tool").getJSONObject("driver");

            String name = driver.optString("name", "");
            if (!DATADOG_SAIST_TOOL_NAME.equalsIgnoreCase(name)) {
                return false;
            }

            // Be tolerant: accept if any version-ish indicator exists (or even drop this check).
            return driver.has("version")
                    || driver.has("semanticVersion")
                    || driver.has("informationUri");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Direct mapping of SAIST rule identifiers to OWASP Benchmark CWE/category types.
     *
     * @param ruleId the rule identifier
     * @return a Type enum containing the CWE number and category id, or null if unmapped
     */
    private Type getTypeFromRuleId(String ruleId) {
        return RULE_ID_TO_TYPE.get(ruleId);
    }

    /**
     * Try to extract CWE from a SARIF result object's properties or nested rule metadata.
     *
     * @param violation SARIF result object
     * @return CWE number or 0 if none found
     */
    private int getCweFromProperties(JSONObject violation) {
        try {
            // properties.tags: look for "CWE-###", "CWE:###", "cwe###"
            if (violation.has("properties")) {
                JSONObject properties = violation.getJSONObject("properties");
                if (properties.has("tags")) {
                    JSONArray tags = properties.getJSONArray("tags");
                    for (int k = 0; k < tags.length(); k++) {
                        String tag = tags.optString(k, "");
                        if (tag.toUpperCase().contains("CWE")) {
                            String cweStr = tag.replaceAll("(?i)cwe[-:]?", "")
                                               .replaceAll("[^0-9]", "");
                            if (!cweStr.isEmpty()) {
                                return Integer.parseInt(cweStr);
                            }
                        }
                    }
                }
                if (properties.has("cwe")) {
                    return properties.optInt("cwe", 0);
                }
            }
        } catch (Exception ignore) {
            // fall through to rule-level extraction
        }

        try {
            if (violation.has("rule")) {
                JSONObject rule = violation.getJSONObject("rule");
                if (rule.has("properties")) {
                    JSONObject ruleProps = rule.getJSONObject("properties");
                    if (ruleProps.has("cwe")) {
                        return ruleProps.optInt("cwe", 0);
                    }
                }
            }
        } catch (Exception ignore) {
            // give up
        }

        return 0;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONArray runs = resultFile.json().getJSONArray("runs");

        TestSuiteResults tr =
                new TestSuiteResults("DatadogSaist", true, TestSuiteResults.ToolType.SAST);

        tr.setTime(resultFile.file());

        for (int i = 0; i < runs.length(); i++) {
            JSONObject run = runs.getJSONObject(i);

            JSONObject driver = run.getJSONObject("tool").getJSONObject("driver");
            if (!driver.has("name")
                    || !driver.getString("name").equalsIgnoreCase(DATADOG_SAIST_TOOL_NAME)) {
                continue;
            }

            // Be tolerant of different version fields
            String toolVersion = driver.optString(
                    "version",
                    driver.optString("semanticVersion", "unknown"));
            tr.setToolVersion(toolVersion);

            if (!run.has("results")) {
                continue;
            }

            JSONArray results = run.getJSONArray("results");

            for (int j = 0; j < results.length(); j++) {
                JSONObject result = results.getJSONObject(j);
                String ruleId = result.optString("ruleId", "");
                if (ruleId.isEmpty()) {
                    continue;
                }

                TestCaseResult tcr = new TestCaseResult();

                // Prefer direct ruleId mapping; fallback to extracting CWE from properties/tags
                Type t = getTypeFromRuleId(ruleId);
                if (t != null) {
                    tcr.setCWE(t.number);
                    tcr.setCategory(t.id);
                } else {
                    int cweFromProperties = getCweFromProperties(result);
                    if (cweFromProperties != 0) {
                        tcr.setCWE(cweFromProperties);
                        tcr.setCategory("saist-cwe-" + cweFromProperties);
                    } else {
                        System.out.println(
                                "WARNING: DatadogSaist parser encountered unmapped rule: " + ruleId);
                        continue;
                    }
                }

                if (tcr.getCWE() == 0) {
                    continue;
                }

                if (!result.has("locations") || result.getJSONArray("locations").length() == 0) {
                    System.out.println(
                            "WARNING: DatadogSaist result missing locations for rule: " + ruleId);
                    continue;
                }

                JSONArray locations = result.getJSONArray("locations");
                String filename = locations
                        .getJSONObject(0)
                        .getJSONObject("physicalLocation")
                        .getJSONObject("artifactLocation")
                        .optString("uri", "");

                if (filename.isEmpty()) {
                    continue;
                }

                // Reduce to basename and require Benchmark test file
                int lastSlash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
                if (lastSlash >= 0 && lastSlash + 1 < filename.length()) {
                    filename = filename.substring(lastSlash + 1);
                }
                if (!filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                    continue;
                }

                int testnumber = testNumber(filename); // static helper on Reader
                if (testnumber < 0) {
                    continue;
                }
                tcr.setNumber(testnumber);

                // Evidence/message
                String evidence = "SAIST finding for rule: " + ruleId;
                if (result.has("message")) {
                    JSONObject msg = result.getJSONObject("message");
                    evidence = msg.optString("text", evidence);
                }
                tcr.setEvidence(evidence);

                tr.put(tcr);
            }
        }
        return tr;
    }
}
