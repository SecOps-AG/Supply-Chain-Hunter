# Triage lessons

<!-- lesson L0001 seed:version-line-restore pattern:version-line-restore -->
## L0001 2026-09-01T00:00:00Z
- package: seed/version-line-restore
- signals: version_line
- triage_verdict: malicious
- analyst_verdict: benign
- pattern: version-line-restore
- rule: Restoring or rewriting a version line, such as a package version field or a version constant, is not a compromise when that is the change.
- source: seed

<!-- lesson L0002 seed:historical-prepare pattern:historical-prepare-not-install -->
## L0002 2026-09-01T00:00:01Z
- package: seed/historical-prepare
- signals: lifecycle_script_edits
- triage_verdict: malicious
- analyst_verdict: benign
- pattern: historical-prepare-not-install
- rule: A historical prepare script is not an install payload. preinstall, install, and postinstall are the install hooks. Removing a prepare script is not an install hook.
- source: seed

<!-- lesson L0003 seed:documented-sandbox pattern:documented-sandbox-api -->
## L0003 2026-09-01T00:00:02Z
- package: seed/documented-sandbox
- signals: literal_shell
- triage_verdict: malicious
- analyst_verdict: benign
- pattern: documented-sandbox-api
- rule: A documented sandbox API is not an install hook and is not malicious by itself.
- source: seed
