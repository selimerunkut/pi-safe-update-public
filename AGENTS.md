# Pi Safe Update Agent Workflow

Use this repository to review and update Pi user-scope packages safely. Do not use `pi update --extensions` or `pi update --all` for packages managed by this workflow.

## Project objective and acceptance criteria

The sole product goal is to update Pi extensions while detecting real malware or backdoors.

A candidate is safe to promote when the evidence shows no high-confidence malware or backdoor. The workflow must not label a package unsafe merely because it uses a normal capability such as process spawning, network access, filesystem access, an executable, a lifecycle declaration, a native dependency, or a declared `.bin` entry. Those are review signals and must be judged against the package's purpose.

Scanner/API/authentication/network failures, known-vulnerability database matches, and dependency metadata anomalies are not by themselves evidence of malware. Optional external-provider outages must be retained as warnings/artifacts and must not block an update. Malformed or ambiguous findings must be classified separately from confirmed malware; they must not be silently converted into a malicious verdict.

High-confidence evidence of obfuscation combined with a payload, credential exfiltration, destructive behavior, unexpected remote code loading, or a genuine malicious/backdoor path must block promotion. Review-model timeouts, malformed review output, and non-malware review findings are `UNVERIFIED` evidence and must not be converted into a malicious verdict. A live-state conflict or same-process promotion failure stops that update, but is not a malware verdict and does not block a later fresh review.

A false-positive block is a workflow defect, not an acceptable security result. Every live update test must verify both sides of the goal: genuine malicious fixtures are blocked, while benign real extensions with expected capabilities can be promoted. The live `update-all` result and retained artifacts are the authoritative validation.

## Commands

```bash
# Check every configured package; update only npm packages that pass every gate.
./pi-safe-update.sh update-all

# Check one configured package at a chosen target.
./pi-safe-update.sh update <source> --to latest

# Local-only verification after changing this repository.
bash tests/test-pi-safe-update.sh
bash tests/test-provider-scan-mvp.sh
```

## Required agent behavior

1. Run `update-all` for routine maintenance. It processes packages sequentially.
2. Read each batch summary and each failed run's `artifacts/security-report.md`.
3. A `BLOCKED` result means the candidate did not pass the security workflow. Do not bypass or suppress the security result. Stale transaction artifacts are not security findings and must not block a fresh candidate review.
4. Lifecycle scripts and changes to declared dependency package trees are candidate-scoped review findings. Inspect them against package purpose; do not block solely because the capability exists. Unrelated changes and high-confidence malicious behavior remain blocking.
5. Pinned Git sources are `SKIPPED_PINNED_GIT`. Advance them only through an explicit, separately reviewed `update <source> --to <full-SHA>` request.
6. Treat scanner timeouts, malformed output, and incomplete/non-malware reviews as distinct `UNVERIFIED` evidence, never as proof of malware. Optional provider/API failures warn and continue; only confirmed malicious evidence blocks promotion. A same-process promotion failure stops that update and reports the failure without creating a new security verdict.
7. Keep package findings candidate-bound. Never reuse an approval, report, or suppression for a different package tree.
8. Before committing code changes, run the Python unit tests and both local shell test suites. Do not run candidate package code outside the updater's sandboxed smoke gate.

Python hashing and filesystem tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Artifacts

Per-package evidence is retained at:

```text
~/.pi/agent/.pi-safe-update/runs/<run-id>/artifacts/
```

`update-all` writes its summary at:

```text
~/.pi/agent/.pi-safe-update/runs/batches/<batch-id>/summary.md
```
