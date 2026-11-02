# Impact-only severity rubric

Severity measures supported consequence, not probability. Never use attacker skill, opportunity, exploit complexity, attempt frequency, exposure frequency, or estimated control-bypass probability. Select the highest row supported by any impact dimension. Scale and criticality characterize consequence only. Confidence independently measures evidence quality.

| Cell | Confidentiality/privacy | Integrity/authority/safety | Availability/recovery | Scale/criticality |
|---|---|---|---|---|
| SR-Critical | Catastrophic or irreversible highest-sensitivity exposure | Root/control-plane trust loss, irreversible systemic corruption, or credible catastrophic physical harm | Unrecoverable loss or catastrophic loss of a mission/safety-critical function | Systemic, cross-tenant, or catastrophic critical-function impact |
| SR-High | Major sensitive-data exposure with serious consequence | Administrative compromise, major unauthorized action, materially wrong consequential decision, or serious physical harm | Prolonged critical-service loss or recovery requiring major intervention | Multiple tenants, large population, or critical function |
| SR-Medium | Bounded exposure with substantive contained consequence | Limited privilege gain, material unauthorized modification, or reversible consequential error | Material degradation/outage with established recovery | One tenant, subsystem, or bounded population |
| SR-Low | Minimal-sensitivity or narrowly local exposure with minor consequence | Minor change without crossing a security boundary or affecting consequential decisions | Brief local disruption with routine recovery | Isolated non-critical asset or small subject set |
| SR-Undetermined | Insufficient cited information to bound a material impact dimension; link an MI | Same | Same | Same |

Every rating names one `SR-*` cell and cites its impact facts. A documented control lowers severity only when its cited behavior caps consequence, scope, or recovery burden. If a missing fact could raise impact, keep the supported base severity and state a separate conditional ceiling, one-clause condition, and gating MI. Confidence is `High` for direct specific evidence, `Medium` when only a non-essential detail is missing, and `Low` when material model/scope detail is missing; confidence never changes severity.
