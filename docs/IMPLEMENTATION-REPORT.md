# Pi safe update implementation report

Date: 2026-07-25

## 2026-08-21 Python workflow migration

- Moved the complete updater workflow into `pi_safe_update/workflow.py` with a thin Python-launching shell entrypoint.
- Kept `transaction.py` only for stable tree hashing and filesystem primitives; removed rollback, reconciliation, and startup recovery from the product workflow.
- Kept provider scans optional and non-blocking on API/auth/network/tool errors.
- Changed database findings, normal package capabilities, and metadata anomalies into candidate evidence rather than automatic malware verdicts.
- Added candidate-specific evidence to the read-only Pi review and retained all provider artifacts.
- Removed the former monolithic Bash backend after shell-shim parity tests passed.

Verification for this update:

- `python3 -m unittest discover -s tests -p 'test_*.py'`: passed 2 tests.
- `bash tests/test-pi-safe-update.sh`: passed 44 assertions.
- `bash tests/test-provider-scan-mvp.sh`: passed 24 assertions.

## Implemented

- `pi-safe-update.sh` is a six-line launcher only.
- `pi_safe_update/workflow.py` owns CLI parsing, isolated staging, scope verification, narrow malware/backdoor patterns, advisory database/signature checks, optional provider invocation, candidate-specific Pi review, sandbox smoke testing, same-process promotion cleanup, and update-all batching.
- `pi_safe_update/transaction.py` provides stable tree hashes and filesystem primitives. Old journals remain retained evidence but are not read by new updates.
- Lifecycle scripts, native binaries, executables, normal process/network/filesystem use, dependency metadata, and provider findings are review evidence. They are not automatic malware verdicts.
- `tests/test-pi-safe-update.sh` includes a confirmed-malware fixture and verifies that benign lifecycle/dependency cases still promote.

## Verification

- `python3 -m unittest discover -s tests -p 'test_*.py'`: passed 2 tests.
- `bash tests/test-pi-safe-update.sh`: passed 44 assertions.
- `bash tests/test-provider-scan-mvp.sh`: passed 24 assertions.
- `bash -n pi-safe-update.sh provider-scan-mvp.sh`: passed.
- `python3 -m py_compile pi_safe_update/*.py`: passed.
- `git diff --check`: passed.

## Live validation

`./pi-safe-update.sh update-all` was run against the real Pi installation. The final batch promoted `pi-subagents` 0.40.0 → 0.54.0 and `pi-web-access` 0.18.0 → 0.24.1 after deterministic checks and sandbox smoke passed. Provider Snyk findings and Semgrep service errors were retained as artifacts and did not block promotion. The Pi review timed out for these large candidates and was recorded as `UNVERIFIED`, not as malware evidence. A confirmed-malware fixture remains blocked in the local suite.

The pre-existing `@juicesharp/rpiv-todo` journal from 2026-08-04 is retained as historical evidence. New updates no longer read it or require rollback metadata. A later clean run updated the package to `2.7.0`; the final `update-all` reported every configured package `CURRENT`.

## Limitations

- Static review is not proof of benign behavior.
- Promotion cleanup is limited to the current process; an interrupted filesystem operation may require an operator to inspect the retained run artifacts.
- `shellcheck` was unavailable on this host.
- Remote `sync-to-remote.sh` remains outside this wrapper and can still run lifecycle-capable remote installs.
