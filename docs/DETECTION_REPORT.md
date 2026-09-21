# SSH Password Guessing Detection Report

## Executive summary

The sample log contains a burst of five failed SSH authentication attempts from `198.51.100.23` within 4 minutes 20 seconds. The activity crossed the configured threshold and generated an alert. Because the data is synthetic, this report demonstrates the investigation workflow rather than documenting a real incident.

## 5W1H analysis

| Question | Evidence-based answer |
|---|---|
| Who? | Source IP `198.51.100.23`; actor identity is unknown. |
| What? | Five failed SSH password attempts against `admin`, `root`, and `test`. |
| When? | 2026-09-16 from 10:00:10 to 10:04:30 UTC. |
| Where? | Synthetic host named `lab`, SSH service. |
| Why? | Intent cannot be established from authentication logs alone. The pattern is consistent with password guessing. |
| How? | Repeated SSH password attempts from one source IP inside a sliding five-minute window. |

## Detection logic

- Threshold: 5 failed attempts
- Window: 5 minutes, sliding
- Grouping field: source IP
- Relevant message: `Failed password`
- MITRE ATT&CK: `T1110.001` — Password Guessing

## Evidence and assessment

The five matching events occur at 10:00:10, 10:01:00, 10:02:00, 10:03:00, and 10:04:30 UTC. They target three usernames. The sample also contains two failed attempts followed by a successful login from another IP, and five slow failures from a third IP. Neither control scenario crosses the rule threshold.

Severity: **Medium (demonstration assessment)**. The burst warrants investigation, but the alert alone does not prove account compromise. No successful login from the detected source appears in the sample.

## Recommended response

1. Confirm whether the source belongs to an approved user, scanner, VPN, or NAT.
2. Search for successful authentication from the source before and after the alert.
3. Review the targeted accounts and their recent activity.
4. Check related firewall, endpoint, and identity-provider logs.
5. Apply rate limiting, key-based authentication, or temporary blocking where appropriate.

## Detection gaps

Slow password guessing can remain below the threshold. Distributed guessing across many source IPs is not correlated. A shared IP may also cause a false positive. Additional rules grouped by username and longer time ranges would help cover those cases.
