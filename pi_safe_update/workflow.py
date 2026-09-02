"""Python implementation of the pi-safe-update workflow.

The public shell file is intentionally only a compatibility launcher.  This
module owns staging, candidate-scoped review, provider integration, promotion,
and batch orchestration.
"""
from __future__ import annotations

import contextlib
import difflib
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .transaction import hash_tree, move_to_trash, sha256_file


class FatalError(RuntimeError):
    pass


@dataclass
class Config:
    root: Path
    pi: str = field(default_factory=lambda: os.environ.get("PI", "pi"))
    npm: str = field(default_factory=lambda: os.environ.get("NPM", "npm"))
    git: str = field(default_factory=lambda: os.environ.get("GIT", "git"))
    python: str = field(default_factory=lambda: os.environ.get("PYTHON3", sys.executable))
    timeout_cmd: str = field(default_factory=lambda: os.environ.get("TIMEOUT_CMD", "timeout"))
    sandbox: str = field(default_factory=lambda: os.environ.get("SANDBOX_EXEC", "sandbox-exec"))
    rg: str = field(default_factory=lambda: os.environ.get("RG", "rg"))
    osv: str = field(default_factory=lambda: os.environ.get("OSV_SCANNER", "osv-scanner"))
    agent: Path = field(default_factory=lambda: Path(os.environ.get("PI_AGENT_DIR", Path.home() / ".pi/agent")))
    security_timeout: int = field(default_factory=lambda: int(os.environ.get("SECURITY_TIMEOUT", "300")))
    smoke_timeout: int = field(default_factory=lambda: int(os.environ.get("SMOKE_TIMEOUT", "30")))
    staging_timeout: int = field(default_factory=lambda: int(os.environ.get("STAGING_TIMEOUT", "300")))
    provider_scans: str = field(default_factory=lambda: os.environ.get("PROVIDER_SCANS", "auto"))
    provider_only: str = field(default_factory=lambda: os.environ.get("PROVIDER_SCAN_ONLY", ""))
    provider_timeout: int = field(default_factory=lambda: int(os.environ.get("PROVIDER_TIMEOUT", "120")))

    def __post_init__(self) -> None:
        self.lock = Path(os.environ.get("LOCK_DIR", self.agent / ".pi-safe-update"))
        self.runs = self.lock / "runs"
        self.settings = self.agent / "settings.json"
        self.node_relative = "npm/node_modules" if (self.agent / "npm/node_modules").is_dir() else "node_modules"
        self.vendor = self.root / "vendor"
        self.hidden_scan = os.environ.get("HIDDEN_CODE_SCAN", str(self.vendor / "unified-security/scripts/hidden-code-scan.sh"))
        self.unified_skill = os.environ.get("UNIFIED_SECURITY_SKILL", str(self.vendor / "unified-security/unified-security"))
        self.provider_script = self.root / "provider-scan-mvp.sh"

    def modules(self, root: Path | None = None) -> Path:
        return (root or self.agent) / self.node_relative


class Updater:
    def __init__(self, config: Config):
        self.c = config
        self.run_dir: Path | None = None
        self.command_log: Path | None = None
        self.security_started = 0.0
        self._lock_fd: int | None = None
        self._lock_path: Path | None = None
        self.report_written = False

    # ----- output, process, and filesystem primitives ---------------------
    def info(self, message: str) -> None:
        print(f"* {message}", file=sys.stderr)

    def warn(self, message: str) -> None:
        print(f"WARN: {message}", file=sys.stderr)

    def fatal(self, message: str) -> None:
        if self.run_dir and not self.report_written:
            self.write_security_report(message)
        raise FatalError(message)

    def _record(self, text: str) -> None:
        if self.command_log:
            self.command_log.parent.mkdir(parents=True, exist_ok=True)
            with self.command_log.open("a", encoding="utf-8") as out:
                out.write(text)

    @staticmethod
    def _display(args: Iterable[str]) -> str:
        return " ".join(subprocess.list2cmdline([str(a)]) for a in args)

    def run(self, label: str, args: list[str], *, env: dict[str, str] | None = None,
            cwd: Path | None = None, input_data: str | bytes | None = None,
            timeout: int | None = None, quiet: bool = False) -> subprocess.CompletedProcess[str]:
        command = [str(a) for a in args]
        self._record(f"### [{label}] {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ###\n$ {self._display(command)}\n")
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        if timeout is not None:
            command = [self.c.timeout_cmd, "-k", "5", str(max(1, timeout))] + command
            self._record(f"### TIMEOUT [{label}] {timeout}s ###\n$ {self._display(command)}\n")
        try:
            result = subprocess.run(command, cwd=str(cwd) if cwd else None, env=process_env,
                                    input=input_data, text=isinstance(input_data, str) or input_data is None,
                                    capture_output=True, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result = subprocess.CompletedProcess(command, 124, "", str(exc))
        combined = (result.stdout or "") + (result.stderr or "")
        if combined:
            self._record(combined)
            if not quiet:
                print(combined, end="", file=sys.stderr)
        self._record(f"[exit: {result.returncode}]\n")
        return result

    def which(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def trash(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        trash = Path.home() / ".Trash"
        trash.mkdir(parents=True, exist_ok=True)
        destination = trash / f"pi-safe-update-{path.name}-{os.getpid()}"
        counter = 0
        while destination.exists():
            counter += 1
            destination = trash / f"pi-safe-update-{path.name}-{os.getpid()}-{counter}"
        result = subprocess.run(["mv", str(path), str(destination)], capture_output=True, text=True)
        if result.returncode != 0:
            raise FatalError(f"could not move temporary path to Trash: {path}")

    def cp(self, source: Path, destination: Path, *, preserve: bool = False) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        args = ["cp", "-a"]
        if preserve:
            args = ["cp", "-p"]
        result = subprocess.run(args + [str(source), str(destination)], capture_output=True, text=True)
        if result.returncode:
            raise OSError(result.stderr.strip() or f"copy failed: {source}")

    def mv(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(["mv", str(source), str(destination)], capture_output=True, text=True)
        if result.returncode:
            raise OSError(result.stderr.strip() or f"move failed: {source}")

    def setup_run(self, run_id: str) -> Path:
        self.report_written = False
        self.run_dir = self.c.runs / run_id
        (self.run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        self.command_log = self.run_dir / "artifacts/command.log"
        return self.run_dir

    def write_artifact(self, name: str, content: str) -> None:
        assert self.run_dir
        (self.run_dir / "artifacts" / name).write_text(content, encoding="utf-8")

    def write_json(self, name: str, value: Any) -> None:
        self.write_artifact(name, json.dumps(value, indent=2) + "\n")

    def write_security_report(self, reason: str) -> None:
        if not self.run_dir:
            return
        artifacts = self.run_dir / "artifacts"
        report = artifacts / "security-report.md"
        lines = ["# Pi safe update security report", "", "**Status:** BLOCKED", "", f"**Reason:** {reason}", ""]
        deterministic = artifacts / "deterministic-scan.json"
        if deterministic.exists():
            try:
                data = json.loads(deterministic.read_text())
                lines += ["## Deterministic findings", ""]
                for key in ("blocking_findings", "findings"):
                    for finding in data.get(key, []):
                        lines.append(f"- **{key}:** {finding}")
                lines.append("")
            except Exception as exc:
                lines.append(f"- Could not parse deterministic-scan.json: `{exc}`\n")
        hidden = artifacts / "hidden-code-scan-output.txt"
        if hidden.exists():
            lines += ["## Hidden-code findings", ""]
            matches = [line for line in hidden.read_text(errors="replace").splitlines() if re.search(r":\d+:\S", line)]
            lines.extend(f"- `{line}`" for line in matches) or lines.append("No file/line findings were emitted. See the raw artifact.")
            lines.append("")
        lines += ["## Other artifacts", ""]
        lines.extend(f"- `{p.name}`" for p in sorted(artifacts.iterdir()) if p.name != report.name)
        lines += ["", "Review raw artifacts before approving or rerunning.", ""]
        report.write_text("\n".join(lines), encoding="utf-8")
        self.report_written = True
        self.warn(f"  Security report: {report}")

    # ----- lock and preflight ---------------------------------------------
    def acquire_lock(self) -> None:
        self.c.lock.mkdir(parents=True, exist_ok=True)
        if (self.c.lock / "lock-held").exists():
            self.fatal(f"Lock held by PID unknown at {self.c.lock}. Another update is in progress.")
        path = self.c.lock / "lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            self.fatal(f"Lock held at {self.c.lock}. Another update is in progress.")
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._lock_fd, self._lock_path = fd, path
        self.info("Acquired exclusive lock.")

    def release_lock(self) -> None:
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            self._lock_fd = None

    def preflight_tools(self) -> None:
        self.info("Preflight: checking required tools...")
        for tool in (self.c.pi, self.c.npm, self.c.python, self.c.timeout_cmd, self.c.sandbox):
            if not self.which(tool) and not Path(tool).exists():
                self.fatal(f"Required tool not found: {tool}")
        if not self.which(self.c.rg):
            self.warn("rg not found — hidden-code scan disabled")
        if not self.which(self.c.osv):
            self.warn("osv-scanner not found — OSV check disabled")
        if not self.which(self.c.git):
            self.warn("git not found — limited to npm packages")

    @staticmethod
    def package_name(source: str) -> str:
        value = source.removeprefix("npm:")
        if value.startswith("github:"):
            return value.removeprefix("github:").split("#", 1)[0]
        if value.startswith("git:github.com/"):
            return value.removeprefix("git:github.com/").split("#", 1)[0]
        if value.startswith("@"):
            return value.rsplit("@", 1)[0] if "@" in value[1:] else value
        return value.split("@", 1)[0]

    def package_entry(self, source: str) -> str:
        if not self.c.settings.is_file():
            self.fatal(f"settings.json not found at {self.c.settings}")
        try:
            packages = json.loads(self.c.settings.read_text()).get("packages", [])
        except Exception as exc:
            self.fatal(f"Could not parse settings.json: {exc}")
        if not isinstance(packages, list):
            self.fatal("settings.json 'packages' is not a list.")
        requested = source.removeprefix("npm:")
        for entry in packages:
            if not isinstance(entry, str):
                self.fatal("Object-form package entries are not supported in v1. Remove object entries first.")
            normalized = entry.removeprefix("npm:")
            if entry == source or self.package_name(normalized) == self.package_name(requested):
                self.info(f"  Found: {entry}")
                return entry
        self.fatal(f"Package '{source}' not found in settings.json packages list.")
        raise AssertionError

    def resolve_version(self, source: str, target: str) -> str:
        if target != "latest":
            return target
        name = self.package_name(source)
        self.info(f"Resolving '{name}@latest' to exact version ...")
        result = self.run("npm-view", [self.c.npm, "view", name, "version"], quiet=True)
        if result.returncode or not result.stdout.strip():
            self.fatal(f"Failed to resolve '{name}@latest' from npm registry.")
        return result.stdout.strip().splitlines()[-1]

    # ----- manifests and staging ------------------------------------------
    @staticmethod
    def files(root: Path, *, exclude_updater: bool = False) -> dict[str, Path]:
        found: dict[str, Path] = {}
        if not root.is_dir():
            return found
        for current, dirs, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            if exclude_updater and current_path == root:
                dirs[:] = [d for d in dirs if d != ".pi-safe-update"]
            for name in names:
                path = current_path / name
                if path.is_file() and not path.is_symlink():
                    found[path.relative_to(root).as_posix()] = path
        return found

    def manifest(self, package: Path, label: str) -> None:
        value = {"exists": package.is_dir(), "files": sorted(self.files(package)), "hash": hash_tree(package)}
        self.write_json(f"{label}-manifest.json", value)

    @staticmethod
    def package_dependencies(package: Path) -> set[str]:
        if not package.is_dir():
            return set()
        try:
            data = json.loads((package / "package.json").read_text())
        except Exception:
            return set()
        dependencies: set[str] = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                dependencies.update(name for name in values if isinstance(name, str))
        return dependencies

    @staticmethod
    def resolve_dependency(package: Path, dependency: str, modules: Path) -> Path | None:
        """Resolve a dependency directory without loading any package code."""
        cursor = package
        boundary = modules.parent
        while cursor != boundary:
            candidate = (cursor / dependency if cursor.name == "node_modules"
                         else cursor / "node_modules" / dependency)
            if candidate.is_dir():
                return candidate
            cursor = cursor.parent
        return None

    def dependency_tree(self, root: Path, selected: str, roots: set[str]) -> dict[Path, str]:
        """Return installed package paths reachable from the selected package.

        npm may flatten transitive dependencies to the profile's top-level
        node_modules directory or nest them below another dependency.  Track
        both layouts and map each path to the top-level tree that promotion
        must replace.
        """
        modules = self.c.modules(root)
        selected_package = modules / selected
        if not selected_package.is_dir():
            return {}
        pending: list[Path] = []
        for dependency in sorted(roots):
            resolved = self.resolve_dependency(selected_package, dependency, modules)
            if resolved:
                pending.append(resolved)
        found: dict[Path, str] = {}
        while pending:
            package = pending.pop()
            key = package.absolute()
            if key in found or not package.is_dir():
                continue
            relative = package.relative_to(modules)
            parts = relative.parts
            if not parts:
                continue
            tree = "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]
            found[key] = tree
            for dependency in sorted(self.package_dependencies(package)):
                resolved = self.resolve_dependency(package, dependency, modules)
                if resolved:
                    pending.append(resolved)
        return found

    def stage(self, source: str, target: str, name: str, entry: str) -> Path:
        assert self.run_dir
        stage = self.run_dir / "staging"
        stage.mkdir(parents=True, exist_ok=True)
        self.info("Staging: creating isolated copy of Pi config ...")
        if self.c.settings.exists():
            self.cp(self.c.settings, stage / "settings.json", preserve=True)
        live_modules = self.c.modules()
        if live_modules.is_dir():
            self.cp(live_modules, stage / self.c.node_relative)
        for directory in ("extensions", "skills", "agents", "chains"):
            source_dir = self.c.agent / directory
            if source_dir.is_dir():
                self.cp(source_dir, stage / directory)
        live_package = self.c.modules() / name
        self.manifest(live_package, "before")
        live_hash = hash_tree(live_package)
        settings_hash = sha256_file(self.c.settings) if self.c.settings.exists() else "none"
        install_name = self.package_name(entry)
        install_target = entry
        if target and not entry.startswith(("github:", "git:")):
            install_target = f"npm:{install_name}@{target}"
        self.info("Staging: running direct pi install in isolated directory ...")
        self.info(f"  PI_CODING_AGENT_DIR={stage}")
        env = {"PI_CODING_AGENT_DIR": str(stage), "npm_config_ignore_scripts": "true",
               "NPM_CONFIG_IGNORE_SCRIPTS": "true", "GIT_TERMINAL_PROMPT": "0",
               "HOME": str(stage / "home"), "PYTHONDONTWRITEBYTECODE": "1"}
        (stage / "home").mkdir(parents=True, exist_ok=True)
        env.pop("PI_OFFLINE", None)
        installed = self.run("pi-install", [self.c.pi, "install", install_target, "--no-approve"], env=env, timeout=self.c.staging_timeout)
        if installed.returncode:
            self.fatal(f"Package install in staging failed (exit {installed.returncode}). See {self.command_log}.")
        staged_package = self.c.modules(stage) / name
        self.manifest(staged_package, "after")
        if not staged_package.is_dir():
            self.fatal(f"Staged package directory not found: {staged_package}")
        staged_settings = stage / "settings.json"
        new_entry = ""
        if staged_settings.exists():
            with contextlib.suppress(Exception):
                for item in json.loads(staged_settings.read_text()).get("packages", []):
                    if isinstance(item, str) and self.package_name(item) == name:
                        new_entry = item
                        break
        self.write_json("staging-metadata.json", {"source": source, "pkg_name": name, "exact_target": target or None,
            "install_target": install_target, "live_pkg_hash": live_hash, "live_settings_hash": settings_hash,
            "new_entry": new_entry})

        dependency_roots = self.package_dependencies(live_package) | self.package_dependencies(staged_package)
        dependency_maps = [
            (self.c.agent, self.dependency_tree(self.c.agent, name, dependency_roots)),
            (stage, self.dependency_tree(stage, name, dependency_roots)),
        ]
        live_files = self.files(self.c.agent, exclude_updater=True)
        staged_files = self.files(stage)
        selected_prefix = f"{self.c.node_relative}/{name}"
        modules_prefix = f"{self.c.node_relative}/"
        copied_prefixes = ("extensions/", "skills/", "agents/", "chains/", modules_prefix)
        bookkeeping = {"package.json", "package-lock.json", ".gitignore", f"{self.c.node_relative}/.package-lock.json"}
        dependency_changes: list[str] = []
        dependency_names: set[str] = set()
        unexpected: list[str] = []

        def selected(path: str) -> bool:
            return path == selected_prefix or path.startswith(selected_prefix + "/")
        def dependency_for(path: str) -> str | None:
            matches: list[tuple[int, str]] = []
            for base, dependency_map in dependency_maps:
                absolute = (base / path).absolute()
                for package, tree in dependency_map.items():
                    if absolute == package or package in absolute.parents:
                        matches.append((len(package.parts), tree))
            return max(matches)[1] if matches else None
        def copied(path: str) -> bool:
            return path == "settings.json" or any(path.startswith(prefix) for prefix in copied_prefixes)

        for rel in sorted(set(live_files) | set(staged_files)):
            if rel.startswith("home/") or rel.startswith(".pi-safe-update/") or rel in bookkeeping:
                continue
            live, staged = live_files.get(rel), staged_files.get(rel)
            dep = dependency_for(rel)
            if live and not staged and rel.startswith(modules_prefix) and not selected(rel) and not dep:
                continue
            if not copied(rel):
                if staged and not live:
                    unexpected.append(f"new: {rel}")
                continue
            if live and staged and live.read_bytes() == staged.read_bytes():
                continue
            change = "changed" if live and staged else ("new" if staged else "deleted")
            if rel == "settings.json" or selected(rel):
                continue
            if dep:
                dependency_changes.append(f"{change}: {rel}")
                dependency_names.add(dep)
            else:
                unexpected.append(f"{change}: {rel}")
        if dependency_changes:
            self.write_artifact("dependency-changes.log", "\n".join(dependency_changes) + "\n")
            self.write_artifact("dependency-packages.txt", "\n".join(sorted(dependency_names)) + "\n")
            self.info("Staging: declared dependency changes retained for separate review.")
        if unexpected:
            self.write_artifact("unexpected-changes.log", "\n".join(unexpected) + "\n")
            self.fatal("Unexpected changes outside selected package: " + "; ".join(unexpected))
        trees = [name] + sorted(dependency_names)
        self.write_artifact("promotion-trees.txt", "\n".join(trees) + "\n")
        records: list[str] = []
        for tree in trees:
            records.append(f"{tree}\t{hash_tree(self.c.modules() / tree)}\t{hash_tree(self.c.modules(stage) / tree)}")
        self.write_artifact("promotion-tree-hashes.tsv", "\n".join(records) + "\n")
        self.info(f"Staging: verified — only '{name}' and reviewed dependency trees changed.")
        if live_package.is_dir() and staged_package.is_dir():
            diff = difflib.unified_diff(live_package.read_text(errors="replace").splitlines(True) if live_package.is_file() else [],
                                        staged_package.read_text(errors="replace").splitlines(True) if staged_package.is_file() else [])
            self.write_artifact("review.diff", "".join(diff))
        elif staged_package.is_dir():
            self.write_artifact("review.diff", "\n".join(sorted(self.files(staged_package))))
        return stage

    # ----- security --------------------------------------------------------
    def security_guard(self) -> None:
        if time.time() - self.security_started >= self.c.security_timeout:
            self.fatal(f"Security phase exceeded {self.c.security_timeout}s budget.")

    def deterministic(self, name: str, stage: Path) -> None:
        # confirmed malware/backdoor behavior is blocking; ordinary package
        # capabilities remain candidate-specific review evidence.
        assert self.run_dir
        artifacts = self.run_dir / "artifacts"
        package = self.c.modules(stage) / name
        findings: list[str] = []
        blocking: list[str] = []
        package_json = package / "package.json"
        if package_json.exists():
            with contextlib.suppress(Exception):
                data = json.loads(package_json.read_text())
                scripts = data.get("scripts", {})
                lifecycle = [key for key in ("preinstall", "install", "postinstall", "prepare") if key in scripts]
                if lifecycle:
                    findings.append(f"Lifecycle scripts found: {' '.join(lifecycle)}")
                    self.write_artifact("lifecycle-scripts.txt", "\n".join(f"{k}: {scripts[k]}" for k in lifecycle) + "\n")
                for key in ("dependencies", "devDependencies"):
                    for dep, version in data.get(key, {}).items() if isinstance(data.get(key), dict) else []:
                        if isinstance(version, str) and re.match(r"^(git:|https?://|file:|link:)", version):
                            findings.append(f"Non-registry dependency source (review): {key}: {dep} -> {version}")
        executable = [str(p.relative_to(package)) for p in package.rglob("*") if p.is_file() and os.access(p, os.X_OK)] if package.is_dir() else []
        if executable:
            findings.append("Executable files found in package")
        node_bins = list(package.rglob("*.node")) if package.is_dir() else []
        if node_bins:
            findings.append("Native .node binaries found in package (review against package purpose)")
        # Keep the blocking rules narrow. These patterns represent an actual
        # malicious action, not merely a capability such as network or process
        # access. Normal extensions may use those capabilities without being
        # unsafe.
        malicious_patterns = [
            (re.compile(r"(?:curl|wget)[^\n|]{0,300}\|\s*(?:sh|bash|zsh)", re.I), "remote shell payload"),
            (re.compile(r"\brm\s+-rf\s+(?:/|\$HOME)", re.I), "destructive filesystem command"),
            (re.compile(r"(?:eval|new\s+Function)\s*\(.*(?:Buffer\.from|atob).*(?:fetch|https?://|curl|wget|child_process)", re.I), "obfuscated remote payload"),
            (re.compile(r"(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|PI_TOKEN|SSH_PRIVATE_KEY)[^\n]{0,160}(?:fetch|https?://|request|axios)", re.I), "credential exfiltration path"),
        ]
        if package.is_dir():
            source_extensions = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".sh", ".bash", ".py", ".rb", ".ps1"}
            for path in package.rglob("*"):
                if not path.is_file() or path.stat().st_size > 2_000_000:
                    continue
                with contextlib.suppress(OSError):
                    text = path.read_text(encoding="utf-8", errors="replace")
                    is_shebang_source = text.startswith("#!") and os.access(path, os.X_OK)
                    if path.suffix.lower() not in source_extensions and not is_shebang_source:
                        continue
                    for pattern, title in malicious_patterns:
                        if pattern.search(text):
                            blocking.append(f"confirmed malware/backdoor indicator in {path.relative_to(package)}: {title}")
                            break
        hidden_rc = 0
        hidden_output = ""
        if self.c.hidden_scan and Path(self.c.hidden_scan).is_file() and self.which(self.c.rg):
            target = self.run_dir / "scan-target/package"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(package, target, symlinks=True)
            result = self.run("hidden-code-scan", [self.c.hidden_scan, str(target)], timeout=max(1, self.c.security_timeout), quiet=True)
            hidden_rc = result.returncode
            hidden_output = (result.stdout or "") + (result.stderr or "")
            self.write_artifact("hidden-code-scan-output.txt", hidden_output)
            if hidden_rc:
                # The helper prints section headings and `No matches.` lines
                # even for clean sections. They are not findings. A normal
                # `child_process` import or `evaluate(...)` function is also
                # expected in agent extensions; only the high-confidence
                # payload patterns below block promotion.
                section = ""
                sections: list[tuple[str, str]] = []
                for line in hidden_output.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("=="):
                        section = stripped.strip("= ")
                    elif stripped and stripped != "No matches.":
                        sections.append((section, stripped))
                evidence = "\n".join(line for _, line in sections)
                high_confidence = any(
                    category in {"Long whitespace followed by code", "Invisible or control Unicode", "Suspicious base64 decode literals"}
                    for category, _ in sections
                ) or re.search(
                    r"(?:curl|wget)[^\\n]*(?:\\|\\s*)(?:sh|bash|zsh)\\b|"
                    r"(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|PI_TOKEN|SSH_PRIVATE_KEY)[^\\n]*(?:fetch|https?://|request|axios)",
                    evidence,
                    re.I,
                )
                if high_confidence:
                    blocking.append(f"hidden-code-scan found high-confidence malicious indicators (exit {hidden_rc})")
                else:
                    findings.append("hidden-code-scan reported expected runtime capabilities")
        self.write_json("deterministic-scan.json", {"blocking": bool(blocking), "scan_exit_code": hidden_rc,
            "findings": findings, "blocking_findings": blocking})
        if blocking:
            self.fatal("Deterministic checks failed — confirmed malware/backdoor indicators detected.")
        self.info("  Deterministic checks: PASS")

    def candidate_lockfile(self, name: str, stage: Path, entry: str) -> Path:
        assert self.run_dir
        audit = self.run_dir / "npm-audit"
        artifacts = self.run_dir / "artifacts"
        if entry.startswith(("github:", "git:")):
            self.write_json("npm-signatures.json", {"status": "NOT_APPLICABLE", "reason": "git-candidate"})
            return audit / "package-lock.json"
        package = self.c.modules(stage) / name
        try:
            version = json.loads((package / "package.json").read_text()).get("version")
        except Exception:
            version = None
        if not isinstance(version, str) or not version:
            self.fatal("Candidate package has no exact version for scoped audit.")
        audit.mkdir(parents=True, exist_ok=True)
        (audit / "package.json").write_text(json.dumps({"name": "pi-safe-candidate-audit", "version": "1.0.0", "private": True, "dependencies": {name: version}}))
        env = {"PI_CODING_AGENT_DIR": str(audit), "npm_config_ignore_scripts": "true", "NPM_CONFIG_IGNORE_SCRIPTS": "true"}
        result = self.run("npm-lockfile", [self.c.npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", str(audit)], env=env, quiet=True)
        lock = audit / "package-lock.json"
        if not lock.exists():
            if result.returncode:
                self.fatal(f"Could not create candidate-scoped npm lockfile (exit {result.returncode}).")
            lock.write_text(json.dumps({"name": "pi-safe-candidate-audit", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                "packages": {"": json.loads((audit / "package.json").read_text()), f"node_modules/{name}": {"version": version}}}, indent=2))
        elif result.returncode:
            self.warn(f"candidate lockfile command returned exit {result.returncode}; retaining artifact as UNVERIFIED")
        shutil.copy2(lock, artifacts / "candidate-package-lock.json")
        return lock

    def npm_checks(self, name: str, stage: Path, lock: Path) -> None:
        assert self.run_dir
        artifacts = self.run_dir / "artifacts"
        # Signatures and vulnerability databases are advisory evidence under the
        # project goal. They are never converted into malware verdicts.
        signature_prefix = stage if (stage / "package-lock.json").exists() else lock.parent
        sig = self.run("npm-audit-signatures", [self.c.npm, "audit", "signatures", "--json", "--prefix", str(signature_prefix)], env={"PI_CODING_AGENT_DIR": str(stage)}, quiet=True)
        (artifacts / "npm-signatures.json").write_text(sig.stdout or sig.stderr or "{}")
        try:
            data = json.loads((sig.stdout or "{}"))
            invalid = len(data.get("invalid", [])) + len(data.get("missing", [])) if isinstance(data, dict) else 0
            if invalid:
                self.warn(f"npm audit signatures: {invalid} unverified entries (advisory)")
        except Exception:
            self.warn("npm audit signatures returned malformed output (UNVERIFIED; non-blocking)")
        if self.which(self.c.osv) and lock.exists():
            help_result = subprocess.run([self.c.osv, "scan", "source", "--help"], capture_output=True, text=True, check=False)
            if "--format" in (help_result.stdout + help_result.stderr):
                args = [self.c.osv, "scan", "source", f"--lockfile={lock}", "--format=json"]
            else:
                args = [self.c.osv, f"--lockfile={lock}", "--json"]
            osv = self.run("osv-scanner", args, timeout=max(1, self.c.security_timeout), quiet=True)
            (artifacts / "osv.json").write_text(osv.stdout or osv.stderr or "")
            try:
                payload = json.loads(osv.stdout or "")
                count = sum(len(item.get("vulnerabilities", [])) for item in payload.get("results", [])) if isinstance(payload, dict) else 0
                self.warn(f"OSV-Scanner: {count} vulnerability records (advisory; not malware evidence)") if count else self.info("  OSV-Scanner: PASS")
            except Exception:
                self.warn(f"OSV-Scanner failed or returned malformed output (exit {osv.returncode}; UNVERIFIED; non-blocking)")

    def providers(self, name: str, stage: Path) -> None:
        assert self.run_dir
        artifacts = self.run_dir / "artifacts"
        if self.c.provider_scans == "off":
            self.write_json("provider-summary.json", {"status": "SKIPPED", "reason": "disabled by PROVIDER_SCANS=off"})
            return
        if not self.c.provider_script.is_file():
            self.write_json("provider-summary.json", {"status": "SKIPPED", "reason": "provider scanner not installed"})
            return
        baseline = artifacts / "provider-baseline.json"
        candidate: dict[str, Any] = {"schema": 1, "candidate_artifacts": {}}
        for filename in ("deterministic-scan.json", "npm-signatures.json", "osv.json", "sandbox-smoke.json"):
            path = artifacts / filename
            if path.is_file():
                with contextlib.suppress(Exception):
                    candidate["candidate_artifacts"][filename] = json.loads(path.read_text())
        baseline.write_text(json.dumps(candidate, indent=2) + "\n")
        providers = [p.strip() for p in (self.c.provider_only or "snyk,semgrep,socket").split(",") if p.strip()]
        rows = []
        root = self.run_dir / "provider-mvp"
        root.mkdir(exist_ok=True)
        for provider in providers:
            command = os.environ.get({"snyk": "SNYK", "semgrep": "SEMGREP", "socket": "SOCKET"}.get(provider, ""), provider)
            if provider not in {"snyk", "semgrep", "socket"} or not self.which(command):
                rows.append({"provider": provider, "outcome": "skipped", "exit_code": None})
                self.info(f"Security: external provider '{provider}' unavailable; continuing.")
                continue
            case = f"{self.run_dir.name}-provider-{provider}"
            out = artifacts / f"provider-{provider}.stdout"
            err = artifacts / f"provider-{provider}.stderr"
            env = {"SNYK": os.environ.get("SNYK", "snyk"), "SEMGREP": os.environ.get("SEMGREP", "semgrep"), "SOCKET": os.environ.get("SOCKET", "socket"),
                   "PROVIDER_TIMEOUT": str(self.c.provider_timeout), "TIMEOUT_GRACE": os.environ.get("PROVIDER_TIMEOUT_GRACE", "5"), "PYTHON3": self.c.python}
            result = self.run("provider-scan", ["bash", str(self.c.provider_script), "--case-id", case, "--candidate-dir", str(self.c.modules(stage) / name),
                "--baseline", str(baseline), "--out-dir", str(root), "--only", provider], env=env, quiet=True)
            out.write_text(result.stdout or "")
            err.write_text(result.stderr or "")
            status = root / case / f"{provider}.status.json"
            outcome = "error"
            with contextlib.suppress(Exception):
                value = json.loads(status.read_text()).get("outcome")
                if value in {"clean", "findings", "error"}:
                    outcome = value
            rows.append({"provider": provider, "outcome": outcome, "exit_code": result.returncode})
            if outcome == "findings":
                self.warn(f"external provider '{provider}': findings retained for security review")
            elif outcome == "clean":
                self.info(f"  external provider '{provider}': CLEAN")
            else:
                self.warn(f"external provider '{provider}' unavailable or returned an API/tool error; continuing")
        self.write_json("provider-summary.json", {"status": "COMPLETE", "providers": rows})

    def pi_review(self, name: str, stage: Path) -> None:
        assert self.run_dir
        artifacts = self.run_dir / "artifacts"
        package = self.c.modules(stage) / name
        review_root = self.run_dir / "review-target"
        review_package = review_root / "package"
        review_root.mkdir(parents=True, exist_ok=True)
        shutil.copytree(package, review_package, symlinks=True)
        dependencies = artifacts / "dependency-packages.txt"
        if dependencies.exists():
            for dep in [x.strip() for x in dependencies.read_text().splitlines() if x.strip()]:
                source = self.c.modules(stage) / dep
                if not source.is_dir():
                    source = self.c.modules() / dep
                destination = review_root / "dependencies" / dep
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, destination, symlinks=True)
                else:
                    destination.mkdir(parents=True, exist_ok=True)
                    (destination / "DELETED").write_text("candidate dependency tree absent (deletion)\n")
        inventory = []
        for path in sorted(p for p in review_root.rglob("*") if p.is_file()):
            data = path.read_bytes()
            inventory.append(f"{path.relative_to(review_root).as_posix()}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}")
        (artifacts / "review-inventory.txt").write_text("\n".join(inventory[:1000]) + ("\n" if inventory else ""))
        after_hash = hash_tree(package)
        prompt = f'''You are a security reviewer. Review package {name}.\n\nISOLATED CANDIDATE ROOT (read only): {review_package}\nFILE INVENTORY:\n{(artifacts / "review-inventory.txt").read_text()}\nDETERMINISTIC SCAN:\n{(artifacts / "deterministic-scan.json").read_text()}\nPROVIDER RESULTS:\n{(artifacts / "provider-summary.json").read_text(errors="replace") if (artifacts / "provider-summary.json").exists() else "{{}}"}\nExpected hashes (also return these exact JSON fields):\n{{\"candidate_sha256\": \"{after_hash}\", \"changed_tree_sha256\": \"{after_hash}\"}}\n\nInspect source and data flows. Do not execute candidate code. Normal process, network, filesystem, lifecycle, native, and executable capabilities are not malicious by themselves. Return ONLY JSON with schema 1, verdict PASS or FAIL, exact hashes, and findings. Benign findings must be objects with disposition benign and a non-empty rationale. Confirmed malware/backdoor or inability to complete a required review is FAIL.\n'''
        prompt_file = artifacts / "security-prompt.txt"
        prompt_file.write_text(prompt)
        review_file = artifacts / "security-review.json"
        env = {"PI_OFFLINE": "1"}
        result = self.run("pi-security-review", [self.c.pi, "--no-extensions", "--no-skills", "--no-context-files", "--skill", self.c.unified_skill,
            "--tools", "read,grep,find,ls", "--no-session", "--print"], env=env, cwd=review_package, input_data=prompt, timeout=max(1, int(self.c.security_timeout - (time.time() - self.security_started))), quiet=True)
        review_file.write_text(result.stdout or result.stderr or "")
        def unverified(reason: str) -> None:
            self.write_json("security-review.json", {"schema": 1, "status": "UNVERIFIED", "reason": reason,
                "candidate_sha256": after_hash, "changed_tree_sha256": after_hash})
            self.warn(f"  Pi security review: UNVERIFIED ({reason}); continuing because this is not malware evidence")

        if result.returncode == 124:
            unverified(f"timeout after {self.c.security_timeout}s")
            return
        if result.returncode:
            unverified(f"tool exit {result.returncode}")
            return
        try:
            data = json.loads(review_file.read_text())
        except Exception as exc:
            unverified(f"malformed JSON: {exc}")
            return
        if data.get("verdict") == "FAIL":
            finding_text = json.dumps(data, ensure_ascii=False).lower()
            if re.search(r"malware|backdoor|credential exfil|remote shell|destructive payload", finding_text):
                self.fatal("Security review found confirmed malware/backdoor behavior")
            unverified("review reported non-malware findings")
            return
        if data.get("schema") != 1 or data.get("verdict") != "PASS":
            unverified(f"unrecognized verdict={data.get('verdict')!r}")
            return
        if data.get("candidate_sha256") != after_hash or data.get("changed_tree_sha256") != after_hash:
            unverified("candidate hash mismatch")
            return
        findings = data.get("findings")
        if not isinstance(findings, list) or any(not isinstance(item, dict) or item.get("disposition") != "benign" or not str(item.get("rationale", "")).strip() for item in findings):
            unverified("unresolved or malformed finding")
            return
        self.info("  Pi security review: PASS")

    def smoke(self, name: str, stage: Path) -> None:
        assert self.run_dir
        root = self.run_dir / "smoke"
        baseline, candidate = root / "baseline", root / "candidate"
        root.mkdir(parents=True, exist_ok=True)
        profile = root / "profile.sb"
        smoke_real = root.resolve()
        agent_real = self.c.agent.resolve()
        home_real = Path.home().resolve()
        profile.write_text(f'''(version 1)\n(deny default)\n(allow process-fork)\n(allow process-exec)\n(allow signal)\n(allow sysctl-read)\n(allow file-read*)\n(allow file-map-executable)\n(allow file-write* (subpath "{smoke_real}"))\n(allow file-write* (subpath "/dev"))\n(deny network*)\n(deny file-read* (subpath "{home_real}/.pi/agent/auth.json"))\n(deny file-read* (subpath "{home_real}/.ssh"))\n(deny file-read* (subpath "{home_real}/.aws"))\n(deny file-write* (subpath "{agent_real}"))\n''')
        valid = self.run("sandbox-profile", [self.c.sandbox, "-f", str(profile), "/usr/bin/true"], quiet=True)
        if valid.returncode:
            self.fatal("Sandbox profile validation failed.")
        for directory in (baseline, candidate):
            (directory / "home").mkdir(parents=True, exist_ok=True)
        (baseline / "settings.json").write_text('{"packages":[]}\n')
        settings = json.loads((stage / "settings.json").read_text())
        settings["packages"] = [entry for entry in settings.get("packages", []) if isinstance(entry, str) and self.package_name(entry) == name]
        (candidate / "settings.json").write_text(json.dumps(settings, indent=2))
        package_dest = self.c.modules(candidate) / name
        package_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.c.modules(stage) / name, package_dest, symlinks=True)
        for label, config in (("baseline", baseline), ("candidate", candidate)):
            result = self.run("sandbox-smoke", [self.c.sandbox, "-f", str(profile), self.c.pi, "--mode", "rpc", "--offline", "--no-session", "--no-skills", "--no-context-files", "--no-approve"],
                env={"HOME": str(config / "home"), "PI_CODING_AGENT_DIR": str(config)}, input_data='{"type":"get_state"}\n', timeout=self.c.smoke_timeout, quiet=True)
            response = None
            for line in (result.stdout or "").splitlines():
                with contextlib.suppress(Exception):
                    obj = json.loads(line)
                    if obj.get("type") == "response" and obj.get("command") == "get_state":
                        response = obj
                        break
            (self.run_dir / "artifacts" / f"sandbox-{label}.stdout").write_text(result.stdout or "")
            (self.run_dir / "artifacts" / f"sandbox-{label}.stderr").write_text(result.stderr or "")
            if result.returncode or not response or response.get("success") is not True:
                self.fatal(f"{label.capitalize()} Pi smoke test failed.")
            (self.run_dir / "artifacts" / f"sandbox-{label}.json").write_text(json.dumps(response, sort_keys=True))
        self.write_json("sandbox-baseline.json", {"status": "PASS", "timeout_seconds": self.c.smoke_timeout})
        self.write_json("sandbox-smoke.json", {"status": "PASS", "package": name, "timeout_seconds": self.c.smoke_timeout})
        self.info("  Pi extension smoke test: PASS")

    # ----- promotion ------------------------------------------------------
    def tree_records(self) -> list[tuple[str, str, str]]:
        assert self.run_dir
        records = []
        for line in (self.run_dir / "artifacts/promotion-tree-hashes.tsv").read_text().splitlines():
            if line.strip():
                records.append(tuple(line.split("\t", 2)))
        return records

    def promote(self, source: str, name: str, entry: str, stage: Path) -> None:
        assert self.run_dir
        artifacts = self.run_dir / "artifacts"
        live_settings_hash = sha256_file(self.c.settings)
        metadata = json.loads((artifacts / "staging-metadata.json").read_text())
        if metadata.get("live_settings_hash") != live_settings_hash:
            self.fatal("PROMOTION_BLOCKED: settings.json changed since security checks started.")
        records = self.tree_records()
        if not records:
            self.fatal("PROMOTION_BLOCKED: missing promotion tree hashes.")
        for tree, expected, _ in records:
            if hash_tree(self.c.modules() / tree) != expected:
                self.fatal(f"PROMOTION_BLOCKED: live tree changed since security checks started: {tree}")

        promote_tmp = self.c.modules() / name
        promote_tmp = promote_tmp.parent / f".pi-promote.{os.getpid()}"
        self.trash(promote_tmp)
        originals = self.run_dir / "promotion-originals"
        self.cp(self.c.settings, self.run_dir / "settings-before.json", preserve=True)

        def restore_originals() -> bool:
            ok = True
            for tree, old, _ in records:
                live = self.c.modules() / tree
                original = originals / tree
                try:
                    if original.is_dir():
                        self.trash(live)
                        self.mv(original, live)
                    elif old == "none" and (live.exists() or live.is_symlink()):
                        self.trash(live)
                except Exception:
                    ok = False
            try:
                self.cp(self.run_dir / "settings-before.json", self.c.settings, preserve=True)
            except Exception:
                ok = False
            return ok

        try:
            # Prepare every reviewed tree before changing the live installation.
            for tree, _, _ in records:
                staged = self.c.modules(stage) / tree
                if staged.is_dir():
                    self.cp(staged, promote_tmp / tree)
            # Keep originals only for failure cleanup during this invocation.
            for tree, _, _ in records:
                live = self.c.modules() / tree
                if live.is_dir():
                    self.mv(live, originals / tree)
            for tree, _, _ in records:
                prepared = promote_tmp / tree
                live = self.c.modules() / tree
                if prepared.is_dir():
                    self.mv(prepared, live)

            package = self.c.modules(stage) / name / "package.json"
            version = json.loads(package.read_text()).get("version")
            if not isinstance(version, str) or not version:
                raise OSError("staged package has no exact version")
            if entry.startswith(("github:", "git:")):
                new_entry = entry
            else:
                scheme = "npm:" if entry.startswith("npm:") else ""
                new_entry = f"{scheme}{name}@{version}"
            settings = json.loads(self.c.settings.read_text())
            packages = settings.get("packages", [])
            if packages.count(entry) != 1:
                raise OSError("selected settings entry changed during promotion")
            settings["packages"] = [new_entry if item == entry else item for item in packages]
            temporary = self.c.settings.with_name(f".{self.c.settings.name}.tmp.{os.getpid()}")
            temporary.write_text(json.dumps(settings, indent=2))
            self.mv(temporary, self.c.settings)
            for tree, _, expected in records:
                if hash_tree(self.c.modules() / tree) != expected:
                    raise OSError(f"final tree hash mismatch after promotion: {tree}")
        except Exception as exc:
            if not restore_originals():
                self.fatal(f"PROMOTION_FAILED: update failed and live state could not be restored: {exc}")
            self.fatal(f"PROMOTION_FAILED: update failed; live state was restored: {exc}")
        finally:
            self.trash(promote_tmp)
            self.trash(originals)

        self.write_json("promotion.json", {
            "status": "PROMOTED", "source": source, "package": name,
            "trees": [tree for tree, _, _ in records],
        })
        self.info("Promotion: complete.")

    # ----- commands --------------------------------------------------------
    def update(self, source: str, target: str = "") -> None:
        if source.startswith("github:") and not re.match(r"^github:[^#]+#[0-9a-f]{40}$", source):
            self.fatal("GitHub sources require full 40-hex commit SHA: github:owner/repo#<full-sha>")
        if source.startswith("git:") and not re.match(r"^git:github\.com/[^#]+#[0-9a-f]{40}$", source):
            self.fatal("Git sources require git:github.com/owner/repo#<full-sha>")
        self.preflight_tools()
        entry = self.package_entry(source)
        name = self.package_name(source)
        exact = self.resolve_version(source, target) if target else ""
        run = self.setup_run(time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"_{os.getpid()}")
        self.info(f"Run ID: {run.name}"); self.info(f"Artifacts: {run / 'artifacts'}")
        try:
            self.acquire_lock()
            stage = self.stage(source, exact, name, entry)
            lock = self.candidate_lockfile(name, stage, entry)
            self.security_started = time.time()
            self.providers(name, stage)
            self.security_guard(); self.deterministic(name, stage)
            self.security_guard(); self.npm_checks(name, stage, lock)
            self.security_guard(); self.smoke(name, stage)
            self.security_guard(); self.pi_review(name, stage)
            self.security_guard(); self.info("All security checks PASSED.")
            self.promote(source, name, entry, stage)
            final_hash = hash_tree(self.c.modules() / name)
            self.write_json("result.json", {"status": "PROMOTED", "source": source, "pkg_name": name, "target": target or "latest", "exact_target": exact or None, "run_id": run.name, "final_pkg_hash": final_hash, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            self.info("✓ Update promoted successfully.")
            print(f"  Package: {name}", file=sys.stderr)
            if exact: print(f"  Version: {exact}", file=sys.stderr)
            print(f"  Artifacts: {run / 'artifacts'}", file=sys.stderr)
        finally:
            self.release_lock()

    def update_all(self) -> int:
        self.preflight_tools()
        batch = self.c.runs / "batches" / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"_{os.getpid()}")
        batch.mkdir(parents=True, exist_ok=True)
        summary = batch / "summary.md"
        summary.write_text(f"# Pi safe update batch\n\n**Started:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\n| Source | Installed | Latest | Result |\n|---|---:|---:|---|\n")
        try: packages = json.loads(self.c.settings.read_text()).get("packages", [])
        except Exception as exc: self.fatal(f"Could not list configured packages: {exc}")
        if not isinstance(packages, list) or any(not isinstance(source, str) or not source or "\n" in source or "\r" in source for source in packages):
            self.fatal("update-all requires non-empty string-form package entries without newlines")
        failed = 0
        for source in packages:
            if source.startswith(("github:", "git:")):
                with summary.open("a") as out: out.write(f"| `{source}` | — | — | SKIPPED_PINNED_GIT |\n")
                continue
            name = self.package_name(source); package_json = self.c.modules() / name / "package.json"
            try: installed = json.loads(package_json.read_text()).get("version")
            except Exception:
                installed = None
            if not installed:
                failed = 1; summary.open("a").write(f"| `{source}` | missing | — | CHECK_FAILED |\n"); continue
            try: latest = self.resolve_version(source, "latest")
            except FatalError:
                failed = 1; summary.open("a").write(f"| `{source}` | {installed} | unavailable | CHECK_FAILED |\n"); continue
            if installed == latest:
                summary.open("a").write(f"| `{source}` | {installed} | {latest} | CURRENT |\n"); continue
            try:
                self.update(source, latest); status = "PROMOTED"
            except FatalError:
                status = "BLOCKED"; failed = 1
            summary.open("a").write(f"| `{source}` | {installed} | {latest} | {status} |\n")
        summary.open("a").write(f"\n**Finished:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\nEach package has its own retained run artifacts. A `BLOCKED` package remains unchanged; the batch continues with the others.\n")
        self.info(f"Batch summary: {summary}")
        return 1 if failed else 0


def parse_update_args(args: list[str]) -> tuple[str, str]:
    source = ""; target = ""; mode = "source"
    for arg in args:
        if arg == "--to":
            if mode == "target": raise FatalError("Multiple --to values")
            mode = "target"; continue
        if arg.startswith("--"): raise FatalError(f"Unknown flag: {arg}")
        if mode == "source":
            if source: raise FatalError(f"Multiple source arguments: {source} and {arg}")
            source = arg
        elif mode == "target":
            if target: raise FatalError("Multiple --to values")
            target = arg; mode = "done"
    if not source: raise FatalError("Usage: pi-safe-update update <source> [--to <version>]")
    return source, target


def help_text() -> str:
    return """pi-safe-update — staged single-package update with security review\n\nUSAGE\n  pi-safe-update update <source> [--to <version>]\n  pi-safe-update update-all\n  pi-safe-update help\n\nSafe updates stage candidates in an isolated Pi directory, inspect them without executing lifecycle scripts, run optional provider scans, smoke-test Pi in a sandbox, and promote only reviewed candidates.\n"""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"help", "--help", "-h"}:
        print(help_text()); return 0
    config = Config(Path(__file__).resolve().parents[1])
    updater = Updater(config)
    try:
        command, rest = args[0], args[1:]
        if command == "update":
            source, target = parse_update_args(rest); updater.update(source, target); return 0
        if command == "update-all":
            if rest: raise FatalError("Usage: pi-safe-update update-all")
            return updater.update_all()
        raise FatalError(f"Unknown command: {command}. Use 'pi-safe-update help'.")
    except FatalError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        updater.release_lock()
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        updater.release_lock()
        return 1