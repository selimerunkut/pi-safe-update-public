# Coding-Agent Operating Workflow

This repository is the only approved updater for the Pi user-scope packages it manages. It stages one package at a time and only promotes a candidate after all gates pass.

## Routine operation

Run:

```bash
./pi-safe-update.sh update-all
```

The command reads the string-form `packages` list in `~/.pi/agent/settings.json` once, then processes entries sequentially:

| Result | Meaning | Agent action |
|---|---|---|
| `CURRENT` | The installed npm package matches the npm `latest` version. | No action. |
| `PROMOTED` | The latest candidate passed every local security gate. | Record the batch summary. |
| `BLOCKED` | At least one gate failed; the live package was not changed. | Read that run's `artifacts/security-report.md`; do not bypass it. |
| `CHECK_FAILED` | Version lookup or installed metadata failed. | Treat as blocked until corrected and rerun. |
| `SKIPPED_PINNED_GIT` | The package is pinned to a Git commit. | Do not move it automatically. Review a new full SHA explicitly. |

The batch continues after a blocked package. Its exit code is non-zero when any package is blocked or cannot be checked.

## Reviewing blocked packages

1. Open the per-package `security-report.md` first. It lists the failure and file/line evidence.
2. Read the linked raw artifacts only as needed.
3. Classify the finding as confirmed malware/backdoor, benign expected behavior, provider/database `UNVERIFIED`, or unresolved.
4. A benign capability or provider outage is not a package-unsafe verdict. Treat a false-positive block as an updater defect and fix the classifier/review path; do not add a generic suppression.
5. A different candidate version requires a new run and a new review.

## Explicit Git updates

Git packages are immutable only when pinned to a full commit SHA. To review a newer commit, update the configured package entry through a separate change, then run:

```bash
./pi-safe-update.sh update github:owner/repo#<40-hex-SHA>
```

Never replace this with a floating branch or tag.

## Code changes to this repository

Before committing an updater or workflow change:

```bash
bash -n pi-safe-update.sh provider-scan-mvp.sh
python3 -m py_compile pi_safe_update/*.py
bash tests/test-pi-safe-update.sh
bash tests/test-provider-scan-mvp.sh
```

The tests use local shims. They must not access the network, Docker, the real Pi directory, or candidate code.
