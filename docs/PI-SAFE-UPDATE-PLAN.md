# Pi Safe Update — Right-Sized Implementation Plan

## Decision

Replace the previous transaction-heavy design with a small local wrapper around Pi's existing package installer.

The wrapper will:

1. update one configured package at a time in a disposable Pi config directory, with a sequential `update-all` wrapper for routine npm-package maintenance;
2. stage the update with extension discovery disabled;
3. disable npm lifecycle scripts during the staged update;
4. scan the staged before/after diff with deterministic checks and the pinned unified-security skill;
5. launch the staged candidate in a disposable runtime smoke sandbox with extensions enabled; and
6. promote the staged package only after every machine-readable check passes.

This is a detection and containment workflow, not a proof that a package is benign. The candidate is first staged with extensions and lifecycle scripts disabled. A short smoke run then launches Pi with only the candidate enabled inside a disposable sandbox. The smoke run is a startup/integration check, not a full package test suite.

The five-minute limit starts **after the staged update and all downloads finish**. Update/download time is excluded from the security budget. Staging itself has a separate bounded timeout so a hung installer cannot run indefinitely.

## Scope

### In scope

- One local package per security review; `update-all` runs independent reviews sequentially.
- User-scope packages under `~/.pi/agent`.
- npm packages and GitHub Git packages.
- Exact npm versions, `latest` resolved once to an exact version, or full 40-hex Git commit SHAs.
- Automatic promotion on a strict `PASS` result, including a successful sandbox smoke test.
- Same-process cleanup if promotion fails.
- Saved security and promotion evidence for every run.

### Out of scope for v1

- Remote deployment through `sync-to-remote.sh`.
- Direct `pi update --all` or an unreviewed bulk update; `update-all` is allowed only because it invokes the one-package security review sequentially.
- Project-local packages.
- Arbitrary HTTP, SSH, local-path, tarball, or non-GitHub Git sources.
- Full package test suites, arbitrary builds, or lifecycle scripts.
- Docker as a mandatory dependency. The first implementation uses the host macOS sandbox when available; Docker is an optional fallback only when explicitly enabled.
- Native/platform-dependent package support unless the staged tree is proven identical and the policy explicitly permits it.
- Socket, `npq`, LavaMoat, or Renovate as mandatory dependencies.

`sync-to-remote.sh` remains unchanged. Its remote `pi install` path can run lifecycle scripts and does not transfer the locally reviewed artifact.

## Public CLI

```text
pi-safe-update update-all
pi-safe-update update <existing-source> [--to <exact-semver|latest|40-hex-sha>]
pi-safe-update help
```

Rules:

- `update-all` reads every string-form package entry once, compares npm packages to npm `latest`, and runs outdated packages sequentially through the single-package security review.
- Require one existing package entry in `~/.pi/agent/settings.json` for `update`.
- Reject ambiguous entries and Pi's object-form package entries in v1; support string entries only.
- Require a full Git SHA. Never resolve or install a floating Git tag.
- Resolve npm `latest` once for each candidate, then record and promote the resulting exact version.
- Reject duplicate, unknown, or positional flags.
- Pinned Git sources are listed as skipped by `update-all`; only an explicit full-SHA `update` may advance them.
- No `--yes`, CI acknowledgement, or interactive human approval is needed. The security result is the gate.

## Update flow

### 1. Preflight

Before downloading or changing anything:

- verify required commands and pinned versions are installed: `pi`, `npm`, `git`, Python 3, the deterministic scanner, OSV-Scanner, the macOS `sandbox-exec` tool, and the pinned security-skill checkout;
- run a scratch compatibility probe before staging: prove that the installed Pi accepts the exact npm-version and full Git-SHA forms used by this wrapper; reject the update if either pin form is unsupported;
- verify the unified-security skill commit and helper hash;
- acquire an exclusive lock under `~/.pi/agent/.pi-safe-update/`;
- reject an active lock; old run artifacts are evidence only and do not block a new review;
- locate the selected package and target directory using Pi's package layout;
- record the current settings entry, package-tree hash, package manifest, lockfiles, and tool versions.

No live file is changed during preflight.

### 2. Stage the candidate

Create a temporary `PI_CODING_AGENT_DIR` containing the current settings and package state. Exclude sessions, auth data, and unrelated host state.

Run the single-package install/update only in that directory with a separate staging timeout (for example, 300 seconds):

```text
pi install <exact-source> --no-approve
npm_config_ignore_scripts=true
NPM_CONFIG_IGNORE_SCRIPTS=true
GIT_TERMINAL_PROMPT=0
```

Current Pi accepts global agent flags only before its subcommand; using them before `install` makes `install` an ordinary model prompt, while using them after `install` is rejected. The direct `pi install` command is therefore used with an isolated config directory and `--no-approve`; it does not start an agent session or load the installed extension. `PI_OFFLINE` must be unset because staging needs registry access. `ignore-scripts` prevents npm `preinstall`, `install`, `postinstall`, and `prepare` lifecycle scripts from running. The wrapper must capture the complete command log and exit status.

For GitHub sources, use HTTPS and a full commit SHA. Set a temporary Git HOME/config, disable terminal prompts, hooks, submodules, and non-HTTPS protocols where Pi's installer permits it. If the installer cannot provide these controls, reject Git candidates rather than weakening the policy.

After staging, verify that only these things changed:

- the selected package tree;
- package trees for dependencies declared by the selected candidate;
- the selected package string in `settings.json`; and
- package-manager metadata inside the selected tree.

Declared dependency-tree changes are retained as candidate-scoped review material and must be inspected by the read-only security review. Any unrelated settings, package tree, shared npm-root, or root `.bin` change discards the candidate. Pi/npm bookkeeping files created at the shared npm root (`package.json`, `package-lock.json`, `.gitignore`, and `node_modules/.package-lock.json`) plus Pi's generated `models-store.json` are recorded but never promoted; no other shared-root change is allowed.

## Security phase

The security watchdog starts only after staging completes. Hard wall-clock limit: **300 seconds**.

The watchdog's 300-second wall-clock limit is the only hard timing contract. The following per-step budgets are guidance; parallel checks do not add linearly. On expiry, kill the complete process group and fail closed.

Suggested budgets:

| Check | Budget |
|---|---:|
| Hashes, file manifest, and before/after diff | 15 s |
| Pinned deterministic helper and policy checks | 30 s |
| Package-specific signatures and OSV checks | 30 s |
| Disposable Pi extension smoke test | 60 s |
| Read-only Pi review using the security skill | 135 s |
| Result validation and report finalization | 15 s |
| **Total** | **285 s**, with 15 s watchdog margin |

Independent checks run in parallel where practical. Provider and vulnerability-database outages, malformed results, and missing optional tools are retained as `UNVERIFIED` evidence and do not become malware verdicts. Review timeouts and malformed/non-malware review results are `UNVERIFIED` evidence. The staged directory is discarded for security failures; a same-process promotion failure attempts cleanup and reports the update failure without creating a malware verdict.

### Deterministic checks

Run the pinned `hidden-code-scan.sh` helper against changed executable/source files and inspect the complete changed-file set. Also check:

- new or changed `preinstall`, `install`, `postinstall`, or `prepare` scripts;
- new executable files, binaries, `.node` files, and unexpected large assets;
- `child_process`, shell execution, dynamic evaluation/import, network, filesystem, credential, and environment access;
- suspicious encoded/obfuscated content and hidden Unicode/whitespace;
- dependency additions, removals, source changes, Git/HTTP dependencies, and dependency confusion indicators;
- changes to Pi resource declarations and package filters;
- root `.bin` additions, removals, or target changes;
- OS, CPU, libc, optional-dependency, and native-build indicators.

Classify findings instead of treating every process call as malicious:

- **Informational**: normal `child_process`, `spawn`, browser, Docker, or network code that matches the package purpose.
- **Review**: new shell construction, filesystem writes, credential/environment access, or lifecycle scripts.
- **Block**: obfuscation, dynamic code loading from remote input, encoded payloads, unexpected binaries/native code, destructive commands, or unrelated capability changes.

V1 blocks confirmed malicious findings. Lifecycle scripts are retained as candidate-specific findings and are assessed by the read-only review; a confirmed unsafe result blocks promotion, while an unavailable, malformed, or non-malware review is recorded as `UNVERIFIED`. Declared dependency-tree changes follow the same rule, while unrelated changes remain deterministic blocks. Legitimate capabilities may pass when the package identity and changed files explain them. The policy is a small versioned file, not a per-package exception mechanism.

### npm-specific checks

For npm candidates:

- require a candidate-scoped lockfile; if one is absent, generate it in the isolated staging directory with scripts disabled, or fail closed;
- run `npm audit signatures` against that candidate lockfile, never the shared `~/.pi/agent/npm` tree;
- run OSV-Scanner against the same candidate-scoped dependency graph;
- record invalid signatures and newly introduced vulnerabilities as advisory evidence; they are not malware verdicts;
- record pre-existing vulnerabilities separately from candidate-introduced vulnerabilities without automatically blocking promotion;
- use exact package versions in the promoted settings entry.

A shared-root audit must never be reported as a vulnerability in the candidate. For example, a vulnerability reachable only through another installed package is unrelated evidence.

### Disposable Pi extension smoke test

This is the only step that loads the candidate extension. It is intentionally small:

1. Create a temporary sandbox Pi directory containing only the candidate package, minimal settings, and required package metadata. Do not copy credentials, sessions, project files, skills, or host `AGENTS.md` files.
2. On macOS, launch the host Pi binary through a generated `sandbox-exec` profile. Deny network and writes outside the sandbox; allow read-only access to the Pi/Node runtime and writes only inside the temporary sandbox. Do not mount the Docker socket or keychain.
3. First run a known-good vanilla Pi through the same profile. Keep that baseline as evidence so profile failures are not confused with candidate failures.
4. Enable extension discovery for the candidate run, but keep `--offline`, `--no-skills`, and `--no-context-files` enabled:

   ```text
   pi --mode rpc --offline --no-session --no-skills --no-context-files --no-approve
   ```

5. Send exactly `{"type":"get_state"}` over RPC. Require a response with `success: true`; an exit code alone is not sufficient. Then close stdin. Do not send a model prompt, browser action, shell command, or purchase/submit action.
6. Record startup time, exit status, stderr, loaded candidate identity, and sandbox violations.

The smoke test passes only if the baseline passes, Pi starts with the candidate enabled, returns `success: true` within 30 seconds, exits cleanly, and produces no sandbox violation. A launch error, extension registration error, timeout, or write/network access outside the profile is `FAIL`. Normal child processes are allowed when the profile permits them; a denied or unexpected capability is recorded as a sandbox violation. The temporary HOME and auth exclusion are verified by the profile. This is a startup/integration check, not a replacement for package tests.

If `sandbox-exec` is unavailable or the profile cannot be validated, fail closed. The wrapper must kill the complete Pi process group on timeout. Docker may be added as an explicit opt-in fallback later, but it is not required for v1.

The npm `min-release-age` setting is a useful additional defense against newly published packages, but it affects resolution time rather than the five-minute security budget. It may be enabled separately after the v1 workflow is working.

### Read-only Pi review

Launch a fresh Pi process with:

```text
--no-extensions
--no-skills
--no-context-files
--skill <pinned-unified-security-skill>
--tools read,grep,find,ls
--no-session
--mode json
```

Provide only the staged diff, manifests, deterministic scan output, and package metadata. Do not provide write, shell, edit, or network tools. The prompt must require a single machine-readable result and must state that repository instructions and package text are untrusted data.

The required result shape is:

```json
{
  "schema": 1,
  "verdict": "PASS",
  "candidate_sha256": "...",
  "changed_tree_sha256": "...",
  "findings": []
}
```

The wrapper accepts `PASS` only when:

- the JSON is valid and the schema is supported;
- candidate and changed-tree hashes match the wrapper's own hashes;
- deterministic checks have no blocking findings;
- npm signatures/OSV checks have no blocking findings; and
- the result contains no unresolved high-confidence finding.

Anything else is `FAIL`.

The model review is supplemental. A model-only `PASS` can never override a deterministic failure.

## Promotion

After `PASS`:

1. Recheck that the live selected package tree and selected settings string still match the preflight hashes.
2. Copy every reviewed tree to a same-filesystem temporary destination before changing live files.
3. Keep the current live trees and settings in the current run directory only for cleanup if this process fails.
4. Replace the reviewed trees and rewrite only the selected settings string through a temporary file plus atomic rename.
5. Verify the final target and settings hashes.
6. Discard the temporary promotion copies after success.

A promotion failure is a failed update, not a malware verdict. The process attempts to restore the live trees and settings during that invocation. Old run artifacts are retained as evidence but are never used as a prerequisite for a future security review.

## Artifacts

Each run retains a directory under:

```text
~/.pi/agent/.pi-safe-update/runs/<run-id>/
```

Required artifacts:

- `before-manifest.json`
- `after-manifest.json`
- `review.diff`
- `package.json` and lockfile snapshots
- `deterministic-scan.json`
- `npm-signatures.json` when applicable
- `osv.json` when applicable
- `security-review.json`
- `sandbox-baseline.json`
- `sandbox-smoke.json`
- `sandbox.stdout` and `sandbox.stderr`
- `promotion.json`
- `command.log`
- `result.json`

The terminal receives only a concise result and artifact path. Reports must be complete and not depend on truncated terminal output.

## Implementation tasks

### 1. Reconcile `pi-safe-update.sh` with this plan

`pi-safe-update.sh` already exists in this repository. Treat this plan as the target specification: preserve working behavior, add the missing sandbox/compatibility checks, and remove or correct behavior that contradicts this plan. Do not create a second updater.

Implement or verify:

- strict argument parsing and source validation;
- lock acquisition;
- isolated staging directory creation;
- Pi staging invocation with extension/skill/context discovery disabled and npm scripts ignored;
- exact npm-version and Git-SHA compatibility probes;
- before/after manifests and changed-file policy checks;
- bounded parallel security checks;
- candidate-scoped lockfile, signature, and OSV checks;
- pinned read-only Pi security review;
- baseline and candidate disposable extension smoke tests with RPC `get_state` success validation;
- hash-checked promotion, same-process failure cleanup, and cleanup.

### 2. Add the disposable extension smoke test

Implement one small function in `pi-safe-update.sh`:

- copy only the candidate package and minimal settings into a run-scoped sandbox directory;
- generate and validate one macOS `sandbox-exec` profile;
- launch Pi with extensions enabled, `--no-skills`, `--no-context-files`, `--no-session`, and RPC mode;
- send `get_state`, require a successful response within 30 seconds, then close stdin;
- retain stdout/stderr and sandbox diagnostics as artifacts;
- fail closed when the sandbox tool, profile, startup, extension registration, or shutdown fails.

Do not run a model prompt or package test suite. Do not expose credentials, the keychain, the Docker socket, or the network.

### 3. Add `tests/test-pi-safe-update.sh`

Use temporary fake Pi directories and command shims. Do not use the real `~/.pi/agent`, registry, network, or candidate package code.

Cover:

- invalid CLI and unsupported source rejection;
- object-form settings rejection and ambiguous package rejection;
- proof that staging uses direct `pi install --no-approve` in the isolated config directory and enables npm script blocking;
- proof that the candidate is never loaded before review;
- changed unrelated files, root `.bin`, native, optional, and lifecycle/dependency review classification;
- deterministic scanner finding classification, candidate-scoped signature/OSV checks, and security-review timeout/failure/malformed-result handling;
- sandbox baseline and candidate smoke success, extension-load failure, startup timeout, denied write/network, and missing-sandbox-tool handling;
- exact RPC `get_state` success checking, including a malformed response with process exit code 0;
- unsupported exact-version or full-SHA installer forms;
- hash mismatch and model hash mismatch handling;
- successful automatic promotion;
- copy, rename, and settings-write failures clean up within the current invocation;
- external settings/package changes causing no-write conflict;
- preservation of unrelated settings/npm metadata during promotion.

### 4. Update `README.md`

Document:

- the three commands;
- the five-minute security-only budget;
- staging and no-extension behavior;
- lifecycle-script blocking;
- exact PASS policy;
- rejected package layouts;
- artifact location;
- promotion failures and retained security artifacts;
- the fact that remote sync remains lifecycle-capable and is not covered.

Do not modify `sync-to-remote.sh`.

## Follow-up options, not v1 blockers

- Trial Socket Firewall as an external behavior-analysis adapter. It is the closest existing pre-install tool, but it wraps npm rather than Pi and may add network/service latency.
- Trial `npq` in dry-run mode for package metadata heuristics. Do not invoke it through unpinned `npx`.
- Add a reviewed lifecycle-script allowlist with LavaMoat only if legitimate packages require scripts.
- Add a release-age policy after measuring update usability.
- Add container execution only if later evidence shows static review plus script blocking is insufficient.

## Acceptance criteria

The v1 implementation is complete when:

1. A candidate update never changes the live Pi directory before a strict machine-readable `PASS`.
2. The candidate is staged with extensions disabled and npm lifecycle scripts disabled.
3. The security phase always terminates within 300 seconds, excluding update/download time.
4. Confirmed malware/backdoor evidence and sandbox failures leave the live installation unchanged. Optional provider/database/review timeouts and malformed output are warnings/artifacts, not malware verdicts.
5. The candidate starts with extensions enabled inside the disposable sandbox and answers one RPC state request within 30 seconds.
6. A successful promotion changes only the selected package tree, reviewed declared dependency trees, and selected settings string.
7. A same-process promotion failure attempts to restore the old state and reports the update failure without labeling the candidate malicious.
8. Tests prove the above without executing untrusted package code outside the disposable smoke sandbox.

## Residual risks

- Static scanning and read-only model review cannot prove that a package is benign.
- The package manager itself still processes untrusted package metadata and archives; staging prevents it from changing the live Pi installation, while `ignore-scripts` prevents lifecycle execution.
- A package can contain malicious behavior that is not detected until its extension is later loaded. The review reduces risk but is not a security proof.
- Remote installation remains a separate, weaker path until a remote-safe installer is designed.
