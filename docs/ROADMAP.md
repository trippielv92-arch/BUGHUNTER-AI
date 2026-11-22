# Roadmap

## Current foundation
- [x] Local owner accounts and account-isolated SQLite projects.
- [x] Manual programme policy review and exact included-scope approval.
- [x] Passive DNS and Certificate Transparency candidate discovery.
- [x] Bounded HTTPS website discovery and endpoint/API inventory.
- [x] Metadata-driven manual vulnerability assessment recommendations.
- [x] Potential finding/evidence records and conservative evidence correlation.
- [x] Persistent local hunt queue, systemd worker integration, progress polling, cooperative stop and restart recovery from the beginning.

## Remaining milestones
1. **Scope intelligence:** exclusions, explicit wildcard/CIDR semantics, programme expiry and rate-limit enforcement. Never convert a wildcard or discovered hostname into authorization without human review.
2. **Worker reliability:** exact checkpoints, safe pause/resume, retry policy, worker health visibility and consistent database configuration.
3. **Vulnerability assessment:** permission-gated, non-destructive verification for access control, IDOR, authentication, injection indicators, SSRF indicators, API authorization and business logic. Sensitive tests require controlled accounts, synthetic data or staging.
4. **Finding lifecycle:** reproducible evidence, confidence rationale, duplicate review, manual confirmation and remediation tracking.
5. **Project dashboard:** unified view of assets, endpoints, job progress, assessment coverage, findings and evidence.
6. **Multi-computer architecture:** central API, PostgreSQL, authenticated worker registration, tenant isolation and remote job orchestration.
7. **Production hardening:** encryption at rest, stronger audit integrity, threat modeling, integration tests, packaging and recovery documentation.

## Safety requirements
- Scope exclusions always override inclusions.
- Discovered assets remain candidates until manually reviewed and explicitly approved.
- No automatic vulnerability confirmation or duplicate merging.
- No destructive or state-changing tests without explicit authorization and controlled test data.
- Worker restart recovery must preserve job history and never claim exact resume when only a restart-from-beginning occurred.
