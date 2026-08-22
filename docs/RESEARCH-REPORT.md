# Research report: npm/Pi extension update security

I found several useful building blocks, but no single tool that exactly matches:

> staged Pi extension update → changed-file review → automatic promotion → five-minute security-check limit.

## Closest existing tools

### Socket Firewall / safe npm

Socket analyzes package behavior and metadata, including install scripts, malware, hidden or obfuscated code, native code, typosquatting, filesystem/network/shell/eval usage, and suspicious update behavior. Its `sfw npm install` wrapper is closest to this design, but it wraps npm rather than Pi's package manager.

### npq

`npq` audits packages before installation. It checks package age, downloads, README/license, install scripts, vulnerabilities, signatures, provenance, repository status, and related metadata. It supports dry-run and strict non-auto-continue behavior. It does not provide staging, changed-file review, or rollback.

### npm native controls

- `--ignore-scripts` prevents npm lifecycle scripts from running.
- `npm audit signatures` verifies registry signatures and provenance where available.
- `min-release-age` rejects newly published versions until they are older than the configured number of days.
- `strict-allow-scripts` can turn unapproved install scripts into hard failures.

### OSV-Scanner

OSV-Scanner is a fast, headless CLI that scans npm lockfiles for known vulnerabilities. It complements the unified-security skill but does not detect new malicious behavior or suspicious code.

### LavaMoat allow-scripts

LavaMoat provides an allowlist for packages permitted to run lifecycle scripts. It is useful if a package genuinely requires installation scripts. It also documents that `ignore-scripts` does not protect against every bin-script attack. It is not included initially.

## Recommended combination

Keep a small staging wrapper and add:

1. npm `--ignore-scripts`;
2. npm signature/provenance verification;
3. OSV-Scanner lockfile scan;
4. the unified-security deterministic helper;
5. the unified-security Pi review; and
6. Socket or npq as an optional pre-install metadata check.

Run independent checks in parallel. Cache results by:

```text
exact package content hash
+ scanner version
+ unified-security commit
+ policy version
```

The security clock remains five minutes. Provider, vulnerability-database, and review timeouts or malformed results are retained as `UNVERIFIED` evidence and do not become malware verdicts. Same-process promotion failures are reported as update failures, not malware verdicts.

## Recommendation

Test Socket Firewall first. If it does not integrate cleanly with Pi, use:

```text
npm controls + OSV-Scanner + unified-security + staging/diff wrapper
```

This gives a fast, mostly local, low-complexity solution without the previous Docker and transaction machinery.

Renovate is useful for recurring dependency PRs, but not for local Pi updates; it creates update PRs and relies on CI/automerge rather than reviewing and promoting a local extension tree.

## Sources

- Socket: https://socket.dev/
- Socket safe npm: https://socket.dev/blog/introducing-safe-npm
- Socket FAQ: https://docs.socket.dev/docs/safe-npm-faq
- npq: https://github.com/lirantal/npq
- npm config: https://docs.npmjs.com/cli/v11/using-npm/config
- npm audit: https://docs.npmjs.com/cli/v11/commands/npm-audit/
- npm registry signatures: https://docs.npmjs.com/verifying-registry-signatures/
- OSV-Scanner: https://github.com/google/osv-scanner
- LavaMoat allow-scripts: https://lavamoat.github.io/guides/allow-scripts/
- Renovate use cases: https://docs.renovatebot.com/getting-started/use-cases/

Original research artifacts:

- `/tmp/npm-security-tools-official.json`
- `/tmp/npm-install-protection-tools.json`
- `/tmp/npq-tool.json`
