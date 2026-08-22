# External Scanner MVP for the Existing Pi Safe-Update Workflow

**Status:** Extension proposal for the implemented local workflow

**Date:** 2026-07-25

**Canonical implementation:** `./pi-safe-update.sh`

## Purpose

Evaluate Snyk, Semgrep, and Socket as optional extensions to the existing Pi package installation and upgrade security workflow.

This is **not** a replacement scanner and not a Markdown-focused workflow. The scan target is the complete staged package:

- JavaScript and TypeScript source;
- executable configuration and package metadata;
- dependencies and lockfiles;
- lifecycle scripts and command execution;
- binaries, native modules, and executable files;
- network, filesystem, environment, and credential access;
- obfuscation, encoded payloads, and hidden Unicode;
- skills, prompts, agent definitions, Markdown, and other resources;
- runtime behavior observed during the isolated smoke launch.

Prompt injection is one threat category among many. Markdown receives special handling only when Pi can load it as model instructions.

## Existing Workflow

The real workflow lives in this project. Do not create a second updater.

```text
pi-safe-update update <existing-source> [--to <version>]
    |
    +-- preflight and exclusive lock
    +-- isolated Pi staging
    |     direct `pi install --no-approve` in an isolated config directory
    |     npm lifecycle scripts disabled
    |     no live credentials copied into staging
    +-- selected-package scope verification and diff
    +-- candidate-scoped lockfile generation
    +-- bounded security phase
    |     deterministic package checks
    |     npm signature verification
    |     OSV-Scanner
    |     disposable sandboxed Pi RPC smoke test
    |     read-only unified-security Pi review
    +-- hash-checked promotion
    +-- retained security and promotion evidence
```

### Existing gates

| Existing gate | Coverage |
|---|---|
| Isolated staging | Uses direct `pi install --no-approve` in an isolated config directory; candidate extensions are not loaded and npm lifecycle scripts are disabled |
| `ignore-scripts` | Prevents npm lifecycle execution during staging and lockfile preparation |
| Scope verification | Rejects unrelated settings, package-tree, or shared-root changes; validates new `.bin` links against declared package `bin` targets |
| Deterministic checks | Lifecycle scripts, executable files, native modules, non-registry dependencies, hidden code, obfuscation, Unicode, and risky runtime capabilities |
| `npm audit signatures` | Registry signature and provenance failures |
| OSV-Scanner | Known dependency vulnerabilities from the candidate-scoped lockfile |
| Sandbox smoke test | Loads only the candidate, offline, without credentials; requires RPC `get_state` success and no sandbox violation |
| Read-only Pi review | Reviews the staged diff and metadata with only read/search tools; package instructions are treated as untrusted data |
| Promotion | Hash-checked replacement, same-process failure cleanup, compare-and-swap conflict handling |

Existing artifacts are retained under:

```text
~/.pi/agent/.pi-safe-update/runs/<run-id>/
```

Relevant implementation files:

- `pi-safe-update.sh`
- `tests/test-pi-safe-update.sh`
- `docs/PI-SAFE-UPDATE-PLAN.md`
- `docs/IMPLEMENTATION-REPORT.md`
- `docs/RESEARCH-REPORT.md`
- `vendor/unified-security/`

The committed `opencode-unified-security-skill` contribution is the deterministic hidden-code helper and security-review guidance. This project consumes a vendored copy.

## Why Evaluate External Providers

The existing workflow already provides containment, deterministic policy checks, known-vulnerability scanning, runtime startup validation, and read-only model review.

The provider MVP must therefore answer one question:

> Does a provider add useful security signal that the existing workflow does not already produce?

Potential gaps worth testing:

- deeper cross-file and data-flow SAST;
- proprietary malicious-package and typosquat intelligence;
- stronger analysis of newly published or behaviorally suspicious dependencies;
- independent prompt/skill analysis;
- lower-noise classification and remediation guidance;
- continuous monitoring after an approved package is installed.

Generic findings already caught by the local workflow are duplication, not unique value.

## Provider Adapter Hypotheses

### Snyk

| Product | Candidate input | Hypothesis |
|---|---|---|
| Snyk Code | Complete staged source tree | Cloud SAST may add cross-file source findings beyond local regex checks and model review |
| Snyk Open Source | Candidate-scoped manifest and lockfile | May add dependency intelligence beyond OSV and npm signatures |
| Snyk Agent Scan | Package-only copy containing skills/prompts/resources | May add independent prompt injection, suspicious download, malicious code, credential, and hidden-Unicode findings |
| Container/IaC | Only actual container or IaC artifacts | Not part of the default Pi package scan |

Constraints:

- Snyk Code uploads source for cloud analysis.
- Open Source scans may invoke package managers. There is no general `--no-exec` switch, so they require scanner isolation.
- Agent Scan is a separate client from the standard `snyk` CLI.
- Agent Scan uploads redacted content and metadata to a proprietary, experimental backend.
- Agent Scan can start discovered MCP configurations; give it only a package copy with no live agent configuration or credentials.
- `monitor` and `--report` create persistent Snyk projects. Use one-time `test` commands during evaluation.

Relevant advisory commands:

```bash
snyk code test --org=<ORG_ID>
snyk test --all-projects --org=<ORG_ID>
```

Do not run container or IaC commands when the candidate contains neither.

### Semgrep

| Product | Candidate input | Hypothesis |
|---|---|---|
| Semgrep Code | Complete staged source tree | Static and cross-file analysis may detect vulnerable source flows missed by deterministic checks |
| Semgrep Supply Chain | Candidate lockfiles | May add reachability or dependency findings beyond OSV |

Constraints:

- `semgrep scan` is suitable for a local unpacked directory and Community Edition rules.
- `semgrep ci` evaluates AppSec Platform policy and expects a Git repository; the MVP can use an ephemeral local repository without GitHub integration.
- Do not use `--allow-local-builds` on an untrusted candidate because it permits package-manager execution.
- Standard source analysis is local. Platform findings and metadata are uploaded; AI features may upload relevant snippets.

Relevant advisory commands:

```bash
semgrep scan --config auto .
semgrep ci --dry-run
semgrep ci
```

The MVP must distinguish Community Edition results from AppSec Platform results rather than treating them as one scanner.

### Socket

| Product | Candidate input | Hypothesis |
|---|---|---|
| Socket Scan | Staged manifests and lockfiles | Proprietary malware, install-script, typosquat, obfuscation, and package-behavior intelligence may add unique pre-install signal |
| Socket Diff | Previous and candidate scan IDs | May provide a useful package-upgrade comparison after basic scanning is validated |

Constraints:

- Standard Socket Scan uploads dependency manifests, not the full candidate source tree.
- Do not use `--reach` during the MVP because reachability mode can install dependencies and invoke ecosystem tooling.
- Temporary scans must not replace the organization's current alerts view.

Relevant advisory command:

```bash
socket scan create \
  --tmp \
  --no-set-as-alerts-page \
  --report \
  --json \
  <STAGED_DIRECTORY>
```

## MVP Architecture

### Optional invocation and promotion behavior

The provider evaluator remains a standalone CLI, but the updater invokes it automatically when the provider CLIs are installed (`PROVIDER_SCANS=auto`, the default). It can be disabled with `PROVIDER_SCANS=off` or limited with `PROVIDER_SCAN_ONLY=snyk|semgrep|socket`.

Provider API, authentication, network, timeout, and CLI errors are retained as artifacts and warnings. They do not fail the main update workflow. Valid provider findings are evidence supplied to the candidate-specific review; they do not automatically prevent promotion. Only confirmed malware/backdoor behavior blocks promotion; a same-process promotion failure is reported separately as an update failure.

Implementation location:

```text
./provider-scan-mvp.sh
```

The harness should accept a copied candidate tree and candidate lockfile produced by either:

- a controlled synthetic fixture; or
- an existing successful `pi-safe-update` run whose candidate hash is retained in the evidence.

It must not read the live package directory, `auth.json`, sessions, project instructions, keychains, SSH configuration, cloud credentials, or the smoke-test HOME.

Provider scans run against a copied staged candidate and use their own bounded provider timeout. Their latency is outside the updater's core 300-second local security budget. This preserves the local fail-closed gates while making external services best-effort dependencies.

### Execution and isolation boundary

Provider authentication does **not** by itself require a container. A staged candidate cannot read a provider token unless a scanner executes candidate-controlled code.

For the MVP, the normal non-executing provider modes run on the host against the copied staged candidate:

- `snyk code test`;
- Semgrep source/Supply Chain analysis without `--allow-local-builds`; and
- standard Socket Scan without `--reach`.

Run the existing deterministic checks against the same staged copy. These scans and checks inspect files and dependency metadata; they do not load the Pi extension.

Use scanner isolation only when a provider mode can execute candidate-controlled tooling:

- Snyk Open Source (`snyk test`), because it may invoke package-manager tooling;
- Snyk Agent Scan, because it may start discovered MCP configurations; and
- any future provider mode whose documented behavior executes a package manager, build, test, MCP server, or candidate command.

Semgrep `--allow-local-builds` and Socket `--reach` are prohibited for untrusted candidates in this MVP, rather than being enabled on the host. The disposable Pi RPC smoke test remains mandatory and is the only workflow step that loads the candidate extension; it always runs inside the existing `sandbox-exec` profile.

Provider credentials are supplied only to the provider CLI process through interactive login or secret-manager injection. Do not place them in the copied candidate, the smoke-test environment, command arguments, artifacts, or repository files.

### Shared inputs

Each provider receives only the minimum applicable input:

| Input | Snyk | Semgrep | Socket |
|---|---:|---:|---:|
| Complete staged source | Code; Agent Scan where applicable | Code | No |
| `package.json` and lockfile | Open Source | Supply Chain | Scan |
| Skills/prompts/resources | Agent Scan | Source rules where applicable | No |
| Live Pi configuration or credentials | Never | Never | Never |

### Native output only

Do not build a provider abstraction, SARIF database, dashboard, or remediation engine during the MVP.

Retain native outputs under one evaluation directory:

```text
provider-mvp/<case-id>/
  baseline.json
  snyk-code.json
  snyk-open-source.json
  snyk-agent-scan.json
  semgrep-scan.json
  semgrep-ci.json
  socket.json
  comparison.md
```

`baseline.json` records findings from the existing deterministic, npm-signature, OSV, sandbox, and Pi-review gates. The comparison must measure provider findings against that baseline.

## Evaluation Corpus

Use a small corpus covering the package as a whole:

1. a known-benign Pi TypeScript extension;
2. a known-benign Pi skill or mixed skill/code package;
3. synthetic source with command execution or data-exfiltration flow;
4. synthetic lifecycle, obfuscation, hidden-Unicode, and encoded-payload cases;
5. synthetic prompt injection in a Pi-loadable instruction file;
6. a known vulnerable dependency lockfile;
7. a suspicious dependency or package-metadata case suitable for Socket intelligence;
8. one real approved package upgrade using retained before/after evidence.

Fixtures contain no real secrets and are never installed into the live Pi directory.

## Evaluation Criteria

For every provider and case, record:

- expected findings detected and missed;
- false positives;
- findings already produced by the existing workflow;
- useful unique findings;
- source, manifests, metadata, or other data uploaded;
- whether candidate code or package managers can execute;
- scan duration and timeout behavior;
- authentication and setup friction;
- output stability and machine readability;
- remediation quality;
- free-tier consumption;
- suitability for an unattended, fail-closed package update.

## Keep or Remove Rule

Keep a provider only if it adds at least one of:

- important unique coverage over the current workflow;
- materially better accuracy or lower noise;
- useful malicious-package intelligence unavailable from OSV/npm;
- operationally valuable monitoring or upgrade comparison;
- simpler replacement for an existing weaker check.

Remove it when it duplicates existing evidence with worse privacy, reliability, latency, or maintenance cost.

Keeping all three is acceptable only if each has a clear role. A likely division is:

- Snyk Agent Scan for skill/prompt analysis;
- Semgrep for source SAST;
- Socket for package supply-chain intelligence.

This is a hypothesis to test, not a predetermined architecture.

## Security and Credential Rules

1. Never put provider tokens in chat, source files, command arguments, artifacts, or committed configuration.
2. Use interactive workstation login or secret-manager injection for unattended runs.
3. Revoke any credential exposed outside its intended secret store.
4. Run provider scans and local static checks only on copies of staged candidates.
5. Run normal non-executing provider modes on that copy; provider authentication alone does not require a container.
6. Use scanner isolation only for a mode that can execute candidate-controlled tooling, including Snyk Open Source and Snyk Agent Scan.
7. Do not enable Semgrep local builds or Socket reachability on untrusted candidates.
8. Always run the Pi extension smoke test in its existing `sandbox-exec` profile; it is the only step that loads the candidate extension.
9. Do not upload private package source without explicit approval.
10. Hash inputs before and after scanning to prove providers did not modify them.
11. Apply bounded per-provider timeouts.
12. A provider error must not be mistaken for a clean result.

## Implementation Plan

Keep the evaluator as a standalone CLI, and invoke it from the updater as an optional external stage. Provider service failures are advisory; valid provider findings are passed into the candidate-specific review. Provider scans use their own timeout and do not extend or replace the updater's local security deadline.

### First runnable scope

Evaluate exactly one non-executing mode from each provider:

| Provider | Command mode | Evidence file |
|---|---|---|
| Snyk | `snyk code test` | `snyk-code.json` |
| Semgrep | authenticated `semgrep ci` in an ephemeral local Git repository | `semgrep-ci.json` |
| Socket | standard temporary Socket Scan, without `--reach` | `socket.json` |

Do **not** implement Snyk Open Source, Snyk Agent Scan, Semgrep `--allow-local-builds`, Socket `--reach`, monitoring, or persistent reporting. Those modes either need scanner isolation or are outside the comparison goal. The updater may block on valid findings from the supported non-executing modes, but never on provider API/tool failure.

### Harness contract

Create `provider-scan-mvp.sh` with this interface:

```text
provider-scan-mvp.sh \
  --case-id <safe-name> \
  --candidate-dir <copied-staged-candidate> \
  --baseline <existing-baseline.json> \
  --out-dir <empty-or-new-output-directory> \
  [--snyk-org <org-id-or-slug>] \
  [--only snyk|semgrep|socket]
```

Rules:

- require absolute, existing candidate and baseline paths; require a valid baseline JSON file and copy it to `--out-dir/<case-id>/baseline.json` before scanning;
- reject the live Pi package directory and require a copied fixture or retained candidate evidence as input;
- require a safe `case-id` and create only `--out-dir/<case-id>/`;
- copy the candidate into a private temporary workspace, excluding `.git`, before each provider receives it;
- hash the supplied candidate before and after the complete run and fail if it changes;
- never print, persist, or accept a provider token as an argument;
- preserve stdout, stderr, exit status, elapsed time, command version, and native JSON for every provider; and
- continue to the other providers after one provider fails, then return non-zero if any requested provider had a tool/authentication/invalid-output failure.

Run each provider with a **120-second** wall-clock limit. On timeout, terminate its complete process group with `SIGTERM`, wait five seconds, then send `SIGKILL` if it remains alive. Record this as an `error` outcome and continue with the remaining providers. The MVP harness is separate from the updater, so these evaluation limits do not change its 300-second promotion contract.

`--only` is for a focused retry. Without it, run all three providers. It must not silently turn a missing provider result into a clean result.

### Authentication and command preflight

The harness uses an existing interactive CLI login or a secret injected by the caller's secret manager. It does not perform login, write credentials, or inspect credential files. Before scanning, verify that `snyk`, `semgrep`, `socket`, `git`, `python3`, and `shasum` are available; record versions without recording credentials.

Use the configured/default organization unless `--snyk-org` is supplied. Do not use `--report`, `monitor`, a remote repository URL, or a provider configuration file created from the candidate.

### Provider invocations

Run every command from the private provider-specific copy. Redirect normal output directly to an artifact file rather than parsing terminal text.

```bash
# Snyk Code; do not add --report.
snyk code test --json-file-output="$case_dir/snyk-code.json" [--org="$snyk_org"]

# Semgrep AppSec Platform; initialize an ephemeral local Git repository with no remote.
semgrep ci --json-output="$case_dir/semgrep-ci.json"

# Socket; temporary scan only, no reachability and no alerts-page replacement.
(cd <candidate-copy> && socket scan create --tmp --no-set-as-alerts-page --no-interactive --report --json .)
```

For Socket, run from the private candidate copy and pass `.`; Socket requires scan targets to be within its working directory. Capture the JSON stdout as `socket.json`. Before the first manual Socket scan, record Socket's then-current `--tmp` visibility and retention behavior in the case comparison. Do not assume that `--tmp` deletes uploaded data; if its retention cannot be confirmed, record that as a residual privacy risk. For Semgrep, initialize the temporary repository without copying the candidate's `.git` directory, without a remote, and with hooks disabled before invoking `semgrep ci`. Never pass `--allow-local-builds`, `--allow-untrusted-validators`, `--reach`, or `--auto-manifest`.

Snyk Code exit `0` means completed with no findings and exit `1` means completed with findings. A missing or invalid native JSON artifact, authentication failure, or other tool failure is recorded as a provider failure, never as a clean scan. Apply the same rule to Semgrep and Socket: policy findings may be recorded as completed findings, but execution/authentication/output failures are errors.

### Evidence and comparison

For each requested provider, write:

```text
provider-mvp/<case-id>/
  baseline.json
  input-before.sha256
  input-after.sha256
  <provider>.stdout
  <provider>.stderr
  <provider>.status.json
  snyk-code.json | semgrep-ci.json | socket.json
  comparison.md
```

`<provider>.status.json` contains only: provider, command mode, CLI version, start/end time, elapsed milliseconds, exit code, outcome (`clean`, `findings`, or `error`), and artifact paths. It must not contain command arguments that could hold credentials or provider responses duplicated from the native JSON.

Generate `comparison.md` from the three status files and the existing baseline. It must identify unique findings, duplicated findings, missed expected findings, false positives, uploaded-data scope, runtime, and errors. No shared schema, database, dashboard, or automatic remediation is part of this MVP.

### Tests

Add local-only tests to `tests/test-provider-scan-mvp.sh`. Use fake `snyk`, `semgrep`, `socket`, and `git` binaries; do not authenticate, access the network, call the real CLIs, invoke Docker, or execute candidate code.

Cover at least:

- argument validation and rejection of a live Pi package path;
- baseline-path validation and copying the baseline before scans begin;
- temporary-copy creation and `.git` exclusion;
- Semgrep ephemeral Git initialization without a remote or active hooks;
- all three normal commands and prohibited-option absence;
- Snyk finding exit `1` with valid JSON being recorded as findings, not a harness error;
- invalid/missing JSON and authentication/tool failures being recorded as errors;
- a 120-second provider timeout being recorded as an error after process-group termination;
- continued execution after one provider failure;
- `--only semgrep` with a missing CLI or authentication failure exiting non-zero rather than reporting a clean result;
- no token value in stdout, stderr, status JSON, comparison, or retained artifacts; and
- candidate hashes unchanged before and after scanning.

### TODO checklist

- [x] Create a benign copied Pi-extension fixture, its baseline JSON, and a synthetic vulnerable fixture outside the live Pi directory.
- [x] Add `provider-scan-mvp.sh` with the contract, baseline handling, safety checks, and timeout behavior above.
- [x] Add provider-specific temporary workspaces, hashes, timeouts, and native-output capture.
- [x] Implement Snyk Code, Semgrep CI, and Socket Scan adapters only.
- [x] Add `comparison.md` generation from native evidence and the existing baseline.
- [x] Add `tests/test-provider-scan-mvp.sh` with fake binaries and run it locally.
- [x] Run the three providers manually against an initial `pi-subagents@0.37.0` staged candidate.
- [ ] Confirm provider account setup: enable Snyk Code for the current organization; authenticate Semgrep in the same CLI environment; Socket authentication works.
- [ ] Confirm and record Socket `--tmp` retention behavior from provider documentation or account controls.
- [ ] Run the full corpus, including synthetic vulnerable and prompt-injection cases.
- [ ] Decide keep/remove for each provider before any integration into `pi-safe-update.sh`.

## Integration Decision After the MVP

After evaluating results:

1. remove providers that add no meaningful value;
2. select the smallest complementary set;
3. decide which selected findings should block promotion;
4. determine whether measured provider latency fits the existing 300-second security phase;
5. integrate only selected adapters into the existing `pi-safe-update.sh` before promotion;
6. add command shims and local-only tests to `tests/test-pi-safe-update.sh`;
7. retain provider JSON alongside the existing run artifacts;
8. keep deterministic failures authoritative—a cloud result can never override them.

Do not change the five-minute contract, add mandatory cloud dependencies, or weaken fail-closed behavior without a separate reviewed change to `PI-SAFE-UPDATE-PLAN.md`.

## Implementation and Live-Test Status

Implemented files:

- `provider-scan-mvp.sh`
- `tests/test-provider-scan-mvp.sh`

Local tests pass with **24 provider-harness tests** and **52 updater assertions**. A live update attempt for `npm:pi-subagents` from `0.35.1` to `0.37.0` staged successfully. Its new root `.bin` links (`pi-subagents`, `jiti`, and `yaml`) were traced to declared package `bin` targets and downgraded to review findings. The package's runtime process-spawning code was also recorded as a review finding, not an automatic block, after correcting a report-heading classification bug. The candidate then reached the read-only Pi review, which failed because the generated diff exceeded the review model's context window; promotion was not attempted. The live installation remained at `0.35.1`; settings remained unchanged.

The rejected staged candidate was then copied outside the live Pi directory and scanned by the provider harness. Results:

| Provider | Result | Note |
|---|---|---|
| Snyk Code | `error` | Current Snyk organization returned HTTP 403 because Snyk Code is not enabled |
| Semgrep CI | `error` | CLI required `semgrep login`; no authenticated platform result was produced |
| Socket Scan | `clean` | Authenticated temporary scan completed successfully in about 7 seconds |

These errors are intentionally not treated as clean results. Provider evidence was retained under the session's temporary `pi-provider-live.*` output directory. This is evaluation evidence, not a promotion result.

### Follow-up authenticated Snyk baseline comparison

A later authenticated Snyk Code scan succeeded for both the retained `pi-subagents@0.37.0` candidate and the installed `0.35.1` package. The baseline returned 33 alerts and the candidate returned 29. Every candidate alert matched a baseline alert by rule, relative path, and flagged sink; all 29 also had an identical flagged source line in the installed baseline. The two alerts present only in the baseline were:

- `javascript/PT` at `src/runs/foreground/chain-execution.ts:314`;
- `javascript/PT` at `src/runs/foreground/subagent-executor.ts:2450`.

This means Snyk reported **no new alert introduced by `0.37.0`** under this comparison. It does not prove that the pre-existing alerts are benign. The retained run artifact is `artifacts/snyk-baseline-comparison.md`.

The updater's no-extension Pi review was also corrected to pass a bounded file inventory and an isolated source copy rather than embedding the whole diff; the former full-diff prompt could exceed the reviewer context window. It now uses Pi `--print`, because `--mode json` emits a JSONL event stream rather than the final review object expected by the validator.

## Current Repository State

As of 2026-07-25:

- the hidden-code helper is committed in `opencode-unified-security-skill` at commit `534fb0e`;
- the updater, tests, plans, reports, and vendored security skill are isolated in this new project;
- the implementation report records 28 passing tests and a successful real extension RPC smoke launch;
- this new repository has not yet been committed and should be reviewed before provider integration changes are layered on top.

## Official Sources

- Snyk CLI: <https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli>
- Snyk CLI code-execution warning: <https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/code-execution-warning-for-snyk-cli>
- Snyk Agent Scan: <https://github.com/snyk/agent-scan>
- Semgrep CLI: <https://semgrep.dev/docs/getting-started/cli>
- Semgrep Supply Chain: <https://semgrep.dev/docs/semgrep-supply-chain/set-up-and-configure>
- Socket CLI: <https://docs.socket.dev/docs/socket-cli>
- Socket Scan: <https://docs.socket.dev/docs/socket-scan>
