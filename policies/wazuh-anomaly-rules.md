# Wazuh custom rule examples

This file is a short pointer and a pair of illustrative snippets. The maintained pack — with rule IDs in the custom 100000+ range, a rule-to-detection map, and a starter dashboard — lives in the companion repository:

**[eu-wazuh-detections](https://github.com/bravo1alpha95-dev/eu-wazuh-detections)**

Those rules have **not** been tested with `wazuh-logtest` against a live Wazuh manager in this project. Validate them on your manager version before use.

## Example: unexpected process opening a listener

```xml
<rule id="100002" level="12">
  <if_sid>530</if_sid>
  <match>nc |ncat |socat |python -m http|busybox</match>
  <description>Unexpected process opening a network listener (possible rogue or backdoor)</description>
  <mitre>
    <id>T1571</id>
  </mitre>
</rule>
```

## Example: multiple failed logins from the same source

```xml
<rule id="100010" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5501</if_matched_sid>
  <same_source_ip />
  <description>Multiple failed logins from the same source IP</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Parent rule IDs such as `530` (process start) and `5501` (failed login) come from default Wazuh rules and can vary by manager version — confirm them before deploying.

For unexpected listeners on the host itself, also use `scripts/anomaly-checks.sh`.
