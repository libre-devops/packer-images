#!/usr/bin/env python3
"""Helpers for the Libre DevOps Packer images.

Every pinned input lives in versions.yml (the build's own tools),
images/<name>/image.yml (ISO, hardening role, audit content) or tools/tools.yml
(what role images install), every hardening setting in
images/<name>/hardening/, and every CIS control an image does not meet in the
exception registry, exceptions.yml. This script is the only reader of those
files, so the justfile, the build and test scripts and CI always agree on them.

A golden image installs from an ISO and hardens itself. A role image names a
golden image as its `base`, starts from its finished disk, and adds tools: it
takes its hardening role, audit content, profile and exceptions from the base,
and can add exceptions of its own.

Usage: uv run scripts/images.py <command> [arguments]. Run with --help for the
commands. EXCEPTIONS_TODAY=YYYY-MM-DD makes the registry checks run as if on
that date, to see what will be due for review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
IMAGES = ROOT / "images"
CACHE = ROOT / ".cache"
OUTPUT = ROOT / "output"
REGISTRY = ROOT / "exceptions.yml"
CATALOGUE = ROOT / "tools" / "tools.yml"
LOCKS = ROOT / "tools" / "locks"

# How the tools in the catalogue install, each an Ansible task file in
# ansible/tools/, and the OS families a package tool must name packages for.
METHODS = ("package", "archive", "python", "tenv", "directory")
FAMILIES = ("Debian", "RedHat")

# The exception registry's rules. An exception is decided for at most a year
# at a time, and warns a month before its review is due.
EXCEPTION_ID = re.compile(r"EX-\d{3}")
KINDS = ("deviation", "manual", "false-positive")
RISKS = ("low", "medium", "high")
STATUSES = ("active", "retired")
MAX_REVIEW_DAYS = 366
REVIEW_WARNING_DAYS = 30

# Lockdown role variables that switch one CIS control, or a whole section, on
# and off, such as rhel9cis_rule_1_4_1 and rhel9cis_section5.
RULE_VAR = re.compile(r"^[a-z0-9]+_rule_(\d+(?:_\d+)+)$")
SECTION_VAR = re.compile(r"^[a-z0-9]+_section\d+(?:_\d+)*$")
CONTROL = re.compile(r"\d+(?:\.\d+)+")

# HashiCorp's release signing key, bundled in keys/hashicorp.asc. Packer
# checksum files must carry a valid signature from it. Published at
# https://www.hashicorp.com/trust/security.
HASHICORP_FINGERPRINT = "C874011F0AB405110D02105534365D9472D7468F"


class Failure(Exception):
    """A problem to report to the user without a traceback."""


# Loading


def load_yaml(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError:
        raise Failure(f"{path.relative_to(ROOT)} does not exist") from None
    if not isinstance(data, dict):
        raise Failure(f"{path.relative_to(ROOT)} is not a YAML mapping")
    return data


def image_names() -> list[str]:
    return sorted(p.parent.name for p in IMAGES.glob("*/image.yml"))


@dataclass
class Image:
    name: str
    path: Path
    spec: dict

    @classmethod
    def load(cls, name: str) -> Image:
        path = IMAGES / name
        if not (path / "image.yml").is_file():
            known = ", ".join(image_names()) or "none"
            raise Failure(f"no image called {name!r} (known: {known})")
        return cls(name, path, load_yaml(path / "image.yml"))

    @property
    def base(self) -> Image | None:
        """The golden image a role image is built from; None for a golden image."""
        name = self.spec.get("base")
        return Image.load(str(name)) if name else None

    @property
    def golden(self) -> Image:
        """The image that carries the hardening: this one, or a role image's base."""
        return self.base or self

    @property
    def lineage(self) -> list[str]:
        """The names whose exceptions apply to this image: its own, then its base's."""
        base = self.base
        return [self.name, base.name] if base else [self.name]

    @property
    def role(self) -> dict:
        return self.golden.spec["hardening"]["role"]

    @property
    def audit(self) -> dict:
        return self.golden.spec["hardening"]["audit"]

    @property
    def role_name(self) -> str:
        return repo_name(self.role["repo"])

    @property
    def audit_name(self) -> str:
        return repo_name(self.audit["repo"])

    @property
    def role_dir(self) -> Path:
        return CACHE / "roles" / self.role_name

    @property
    def audit_archive(self) -> Path:
        return CACHE / "audit" / f"{self.audit_name}-{self.audit['commit']}.tar.gz"

    def targets(self) -> list[str]:
        """Source types declared in the Packer templates, such as qemu."""
        found = set()
        for template in self.path.glob("*.pkr.hcl"):
            found.update(re.findall(r'^source\s+"([\w-]+)"', template.read_text(), re.MULTILINE))
        return sorted(found)


def repo_name(url: str) -> str:
    return url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]


# Hardening profile


def squash(text: object) -> str:
    """Folded YAML text as one line."""
    return " ".join(str(text or "").split())


@dataclass
class Setting:
    var: str
    value: object
    reason: str
    source: str
    exception: str = ""

    @property
    def disabled_control(self) -> str | None:
        """The CIS control this setting switches off, if it switches one off."""
        match = RULE_VAR.match(self.var)
        return match.group(1).replace("_", ".") if match and self.value is False else None


@dataclass
class Profile:
    """How an image applies its lockdown role on one target."""

    tag: str
    settings: list[Setting]
    # Filesystem kernel modules left loadable, when the harden step blocks the
    # rest; and the exception that records them.
    keep_modules: list[str] | None = None
    keep_modules_exception: str = ""
    # Services the default firewall zone allows, when the harden step sets them.
    firewall_services: list[str] | None = None

    def disabled_controls(self) -> set[str]:
        return {c for c in (s.disabled_control for s in self.settings) if c}


def load_profile(image: Image, target: str) -> Profile:
    """The CIS profile tag and the merged settings for one target. A role image has its base's."""
    image = image.golden
    hardening = image.path / "hardening"
    common = load_yaml(hardening / "common.yml")
    target_file = hardening / f"{target}.yml"
    if not target_file.is_file():
        raise Failure(f"{target_file.relative_to(ROOT)} does not exist: every target needs its own hardening file, even if empty")
    overlay = load_yaml(target_file)

    tag = overlay.get("profile", common.get("profile"))
    if not tag:
        raise Failure(f"{image.name}: no profile in hardening/common.yml")

    merged: dict[str, Setting] = {}
    for source, data in (("common.yml", common), (target_file.name, overlay)):
        for entry in data.get("settings") or []:
            merged[entry["var"]] = Setting(entry["var"], entry["value"], squash(entry.get("reason")), source, str(entry.get("exception") or ""))
    modules = overlay.get("filesystem_modules", common.get("filesystem_modules")) or {}
    services = overlay.get("firewall_services", common.get("firewall_services"))
    return Profile(
        tag,
        list(merged.values()),
        [str(m) for m in modules["keep"]] if "keep" in modules else None,
        str(modules.get("exception") or ""),
        [str(s) for s in services] if isinstance(services, list) else None,
    )


def role_defaults(image: Image) -> set[str]:
    if not image.role_dir.is_dir():
        raise Failure(f"{image.role_name} is not fetched: run `just deps {image.name}` first")
    names: set[str] = set()
    defaults = image.role_dir / "defaults"
    for path in sorted([defaults / "main.yml", *defaults.glob("main/*.yml")]):
        if path.is_file():
            names.update((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).keys())
    return names


def role_controls(image: Image) -> set[str]:
    """The CIS controls the pinned role implements, from its rule variables."""
    return {m.group(1).replace("_", ".") for m in map(RULE_VAR.match, role_defaults(image)) if m}


# The exception registry


@dataclass
class Entry:
    """One decision in exceptions.yml: CIS controls an image does not meet."""

    id: str
    title: str
    kind: str
    risk: str
    status: str
    # "<image>" or "<image>/<target>" to the controls it covers there.
    controls: dict[str, list[str]]
    reason: str
    mitigation: str
    decided_by: str
    decided_on: date | None
    review_by: date | None
    findings: dict | None
    raw: dict = field(repr=False)

    @property
    def active(self) -> bool:
        return self.status == "active"

    def covers(self, image: str, target: str | None = None) -> list[str]:
        """The controls this entry covers for an image, or one of its targets."""
        found = list(self.controls.get(image, []))
        for key, controls in self.controls.items():
            if key.startswith(f"{image}/") and (target is None or key == f"{image}/{target}"):
                found += controls
        return found


def image_covers(entry: Entry, image: Image, target: str | None = None) -> list[str]:
    """The controls an entry covers for an image: its own, and for a role image its base's too."""
    found: list[str] = []
    for name in image.lineage:
        found += [c for c in entry.covers(name, target) if c not in found]
    return found


def allowed_findings(entry: Entry, names: list[str]) -> list[str] | None:
    """The findings an entry accepts for an image (by its lineage): one list for all, or a list per image."""
    if not isinstance(entry.findings, dict):
        return None
    allowed = entry.findings.get("allowed")
    if isinstance(allowed, dict):
        allowed = next((allowed[name] for name in names if name in allowed), None)
    return [str(a) for a in allowed] if isinstance(allowed, list) else []


def as_date(value: object) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def today() -> date:
    override = os.environ.get("EXCEPTIONS_TODAY")
    if override:
        parsed = as_date(override)
        if not parsed:
            raise Failure(f"EXCEPTIONS_TODAY={override} is not a YYYY-MM-DD date")
        return parsed
    return date.today()


def load_registry() -> list[Entry]:
    entries = []
    for raw in load_yaml(REGISTRY).get("exceptions") or []:
        raw = raw if isinstance(raw, dict) else {}
        controls = raw.get("controls") if isinstance(raw.get("controls"), dict) else {}
        entries.append(
            Entry(
                id=str(raw.get("id") or ""),
                title=squash(raw.get("title")),
                kind=str(raw.get("kind") or ""),
                risk=str(raw.get("risk") or ""),
                status=str(raw.get("status") or ""),
                controls={str(k): [str(c) for c in (v if isinstance(v, list) else [v])] for k, v in controls.items()},
                reason=squash(raw.get("reason")),
                mitigation=squash(raw.get("mitigation")),
                decided_by=squash(raw.get("decided_by")),
                decided_on=as_date(raw.get("decided_on")),
                review_by=as_date(raw.get("review_by")),
                findings=raw.get("findings"),
                raw=raw,
            )
        )
    return entries


def entry_problems(entry: Entry, on: date) -> list[str]:
    """What is wrong with one registry entry on its own, as of a date."""
    problems = []
    where = entry.id or "an entry with no id"
    if not EXCEPTION_ID.fullmatch(entry.id):
        problems.append(f"{where}: the id must look like EX-001")
    for name in ("title", "reason", "decided_by"):
        if not getattr(entry, name):
            problems.append(f"{where}: no {name}")
    if entry.kind not in KINDS:
        problems.append(f"{where}: kind must be one of {', '.join(KINDS)}")
    if entry.risk not in RISKS:
        problems.append(f"{where}: risk must be one of {', '.join(RISKS)}")
    if entry.status not in STATUSES:
        problems.append(f"{where}: status must be one of {', '.join(STATUSES)}")
    if entry.kind == "deviation" and not entry.mitigation:
        problems.append(f"{where}: a deviation needs a mitigation: what reduces the risk, or what a deployment must do")

    if not entry.decided_on or not entry.review_by:
        problems.append(f"{where}: decided_on and review_by must be YYYY-MM-DD dates")
    else:
        if entry.decided_on > on:
            problems.append(f"{where}: decided_on {entry.decided_on} is in the future")
        if entry.review_by <= entry.decided_on:
            problems.append(f"{where}: review_by must be after decided_on")
        elif (entry.review_by - entry.decided_on).days > MAX_REVIEW_DAYS:
            problems.append(f"{where}: review_by is more than a year after decided_on; decide again at least yearly")
        if entry.active and entry.review_by < on:
            problems.append(
                f"{where}: its review was due on {entry.review_by}. Review it: record the new decision with today's "
                f"decided_on and a new review_by, or retire it"
            )

    if entry.status == "retired" and (not as_date(entry.raw.get("retired_on")) or not squash(entry.raw.get("retired_reason"))):
        problems.append(f"{where}: a retired entry needs retired_on and retired_reason")

    if not entry.controls or not any(entry.controls.values()):
        problems.append(f"{where}: controls must map each image to the CIS controls it covers there")
    for key, controls in entry.controls.items():
        for control in controls:
            if not CONTROL.fullmatch(control):
                problems.append(f"{where}: {key} control {control!r} is not a CIS control number such as 1.4.1")
        if len(set(controls)) != len(controls):
            problems.append(f"{where}: {key} lists a control twice")

    if entry.findings is not None:
        findings = entry.findings if isinstance(entry.findings, dict) else {}
        allowed = findings.get("allowed")
        try:
            groups = re.compile(str(findings.get("pattern", ""))).groups
        except re.error as error:
            problems.append(f"{where}: findings.pattern does not compile: {error}")
        else:
            if groups != 1:
                problems.append(f"{where}: findings.pattern needs exactly one capture group, the finding")
        lists = list(allowed.values()) if isinstance(allowed, dict) else [allowed]
        if not lists or not all(isinstance(a, list) and a for a in lists):
            problems.append(f"{where}: findings.allowed must list the findings the exception accepts, or map each image to its list")
        elif isinstance(allowed, dict):
            images = {key.partition("/")[0] for key in entry.controls}
            for name in sorted(set(map(str, allowed)) - images):
                problems.append(f"{where}: findings.allowed names {name}, which the entry does not cover")
    return problems


def registry_problems(entries: list[Entry], on: date) -> list[str]:
    """Everything wrong with the registry, including against the images and their pinned roles."""
    problems = []
    names = set(image_names())
    seen: set[str] = set()
    # (image, control) to the (entry, target) pairs covering it; an empty
    # target means every target.
    coverage: dict[tuple[str, str], list[tuple[str, str]]] = {}
    previous = ""
    for entry in entries:
        problems += entry_problems(entry, on)
        if entry.id in seen:
            problems.append(f"{entry.id}: the id is used twice")
        if previous and natural_key(entry.id) < natural_key(previous):
            problems.append(f"{entry.id}: keep entries in id order (it comes after {previous})")
        seen.add(entry.id)
        previous = entry.id
        if not entry.active:
            continue
        for key, controls in entry.controls.items():
            name, _, target = key.partition("/")
            if name not in names:
                problems.append(f"{entry.id}: there is no image called {name!r}")
                continue
            image = Image.load(name)
            if target and target not in image.targets():
                problems.append(f"{entry.id}: {name} has no {target!r} target")
            known = role_controls(image)
            for control in controls:
                if control not in known:
                    problems.append(f"{entry.id}: {image.role_name} {image.role['version']} has no control {control} for {name}")
                for other, other_target in coverage.get((name, control), []):
                    if other != entry.id and (not target or not other_target or target == other_target):
                        problems.append(f"{entry.id}: {key} control {control} is already covered by {other}")
                coverage.setdefault((name, control), []).append((entry.id, target))
    # A role image inherits its base's exceptions, so its own must not repeat them.
    for (name, control), covering in coverage.items():
        base = Image.load(name).base
        for entry_id, target in covering if base else []:
            for other, other_target in coverage.get((base.name, control), []):
                if not target or not other_target or target == other_target:
                    problems.append(f"{entry_id}: {name} control {control} is already covered by {other} for its base, {base.name}")
    return problems


def find_entry(entries: list[Entry], entry_id: str) -> Entry | None:
    return next((e for e in entries if e.id == entry_id), None)


def due_soon(entries: list[Entry], on: date) -> list[str]:
    return [
        f"{e.id} ({e.title}) is due for review on {e.review_by}"
        for e in entries
        if e.active and e.review_by and 0 <= (e.review_by - on).days <= REVIEW_WARNING_DAYS
    ]


# The tool catalogue

# A pinned archive's SHA-256, with the version it was pinned for.
SHA256_PIN = re.compile(r"^\s*sha256:\s*\"?([0-9a-f]{64})\"?\s*#\s*(\S+)\s*$", re.MULTILINE)


def load_catalogue() -> dict[str, dict]:
    tools = load_yaml(CATALOGUE).get("tools") or {}
    return {str(name): (spec if isinstance(spec, dict) else {}) for name, spec in tools.items()}


def tool_blocks(text: str) -> dict[str, str]:
    """Each tool's lines in tools/tools.yml, by name, to check and rewrite its pins in place."""
    blocks: dict[str, str] = {}
    name = None
    for line in text.splitlines(keepends=True):
        match = re.match(r"^  ([\w.-]+):\s*$", line)
        if match:
            name = match.group(1)
            blocks[name] = ""
        elif re.match(r"^\S", line):
            name = None
        if name:
            blocks[name] += line
    return blocks


def image_tools(image: Image, catalogue: dict[str, dict]) -> list[str]:
    """The tools an image installs, in install order: each one after the tools it requires."""
    order: list[str] = []
    visiting: list[str] = []

    def visit(name: str) -> None:
        if name in order:
            return
        if name not in catalogue:
            raise Failure(f"{image.name}: tool {name!r} is not in tools/tools.yml")
        if name in visiting:
            raise Failure(f"tools/tools.yml: {name} requires itself, through {', '.join(visiting)}")
        visiting.append(name)
        for required in catalogue[name].get("requires") or []:
            visit(str(required))
        visiting.pop()
        order.append(name)

    for name in image.spec.get("tools") or []:
        visit(str(name))
    return order


def fill(template: object, tool: dict) -> str:
    return str(template).replace("{version}", str(tool.get("version", "")))


def python_interpreter(name: str, catalogue: dict[str, dict]) -> str:
    """The interpreter a python tool runs on: the one the package tool it requires names."""
    for required in catalogue[name].get("requires") or []:
        interpreter = (catalogue.get(str(required)) or {}).get("interpreter")
        if interpreter:
            return str(interpreter)
    return ""


def render_tool(name: str, catalogue: dict[str, dict]) -> dict:
    """One tool as the Ansible tools step and the test take it."""
    tool = catalogue[name]
    out: dict = {"name": name, "method": tool["method"]}
    for key in ("packages", "files", "extract_to", "commands", "modules", "environment", "configure", "package", "tenv", "path", "group", "members"):
        if key in tool:
            out[key] = tool[key]
    if "expect" in tool:
        out["expect"] = [str(e) for e in tool["expect"]] if isinstance(tool["expect"], list) else [str(tool["expect"])]
    if "check" in tool:
        out["check"] = [str(c) for c in tool["check"]] if isinstance(tool["check"], list) else [str(tool["check"])]
    if "version" in tool:
        out["version"] = str(tool["version"])
    if tool["method"] == "archive":
        out["url"] = fill(tool["url"], tool)
        out["sha256"] = str(tool["sha256"])
    if tool["method"] == "python":
        out["lock"] = str(LOCKS / f"{name}.txt")
        out["interpreter"] = python_interpreter(name, catalogue)
    if "repo_files" in tool:
        out["repo_files"] = {str(dest): str(ROOT / str(src)) for dest, src in tool["repo_files"].items()}
    return out


def catalogue_problems(catalogue: dict[str, dict]) -> list[str]:
    """Everything wrong with tools/tools.yml."""
    problems = []
    blocks = tool_blocks(CATALOGUE.read_text(encoding="utf-8"))
    for name, tool in catalogue.items():
        where = f"tools/tools.yml {name}"
        method = tool.get("method")
        if method not in METHODS:
            problems.append(f"{where}: method must be one of {', '.join(METHODS)}")
            continue
        if not tool.get("description"):
            problems.append(f"{where}: no description")
        requires = [str(r) for r in tool.get("requires") or []]
        for required in requires:
            if required not in catalogue:
                problems.append(f"{where}: requires {required}, which is not in the catalogue")
        version = str(tool.get("version") or "")
        if method == "package":
            packages = tool.get("packages")
            if not isinstance(packages, dict) or not all(isinstance(packages.get(f), list) and packages.get(f) for f in FAMILIES):
                problems.append(f"{where}: packages must list the packages for each of {', '.join(FAMILIES)}")
        elif method in ("archive", "python", "tenv") and not version:
            problems.append(f"{where}: a {method} tool needs a pinned version")
        elif version and not re.search(r"#\s*renovate:[^\n]*\n\s*version:", blocks.get(name, "")):
            problems.append(f"{where}: put a `# renovate:` comment on the line above version, so Renovate bumps it")

        if method == "archive":
            if "{version}" not in str(tool.get("url", "")):
                problems.append(f"{where}: url must contain {{version}}")
            pin = SHA256_PIN.search(blocks.get(name, ""))
            if not pin:
                problems.append(f"{where}: no sha256 pinned: run `just pin-tools {name}`")
            elif pin.group(2) != version:
                problems.append(f"{where}: sha256 was pinned for {pin.group(2)}, not {version}: run `just pin-tools {name}`")
            files = tool.get("files")
            extract_to = tool.get("extract_to")
            if extract_to is not None and not (isinstance(extract_to, str) and extract_to.startswith("/opt/")):
                problems.append(f"{where}: extract_to must be a directory under /opt")
            if extract_to is None and (not isinstance(files, dict) or not files):
                problems.append(f"{where}: files must map each command to its path in the archive, or extract_to name where the whole archive goes")
        if method == "python":
            if not tool.get("package"):
                problems.append(f"{where}: no package, the name on PyPI")
            if not tool.get("commands") and not tool.get("modules"):
                problems.append(f"{where}: list its commands, or the modules to run as commands")
            if "uv" not in requires:
                problems.append(f"{where}: a python tool installs with uv, so it must require uv")
            if not re.search(r"python(\d+\.\d+)$", python_interpreter(name, catalogue)):
                problems.append(f"{where}: must require a package tool that names its interpreter, such as python")
            lock = LOCKS / f"{name}.txt"
            if not lock.is_file():
                problems.append(f"{where}: no {lock.relative_to(ROOT)}: run `just pin-tools {name}`")
            elif tool.get("package") and not re.search(
                rf"^{re.escape(str(tool['package']))}=={re.escape(version)}\b", lock.read_text(encoding="utf-8"), re.MULTILINE | re.IGNORECASE
            ):
                problems.append(f"{where}: {lock.relative_to(ROOT)} is not for {tool['package']} {version}: run `just pin-tools {name}`")
        if method == "tenv":
            if not any("tenv" in ((catalogue.get(r) or {}).get("files") or {}) for r in requires):
                problems.append(f"{where}: must require the tool that installs tenv")
            if not tool.get("tenv"):
                problems.append(f"{where}: no tenv, the tenv subcommand for the tool, such as tf")

        if method == "directory":
            if not (isinstance(tool.get("path"), str) and tool["path"].startswith("/opt/")):
                problems.append(f"{where}: path must be a directory under /opt")
            if not (isinstance(tool.get("group"), str) and re.fullmatch(r"[a-z_][a-z0-9_-]*", tool["group"])):
                problems.append(f"{where}: group must be a group name")
            members = tool.get("members")
            if not isinstance(members, list) or not members or not all(isinstance(m, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", m) for m in members):
                problems.append(f"{where}: members must list the account names that may write to it")
            if not any(((catalogue.get(r) or {}).get("packages") or {}).get("Debian") == ["acl"] for r in requires):
                problems.append(f"{where}: must require the acl tool, for its default ACLs")
        if "expect" in tool and not (isinstance(tool["expect"], str) or (isinstance(tool["expect"], list) and all(isinstance(e, str) for e in tool["expect"]))):
            problems.append(f"{where}: expect must be a string, or a list of them, that the checks' output must contain")

        environment = tool.get("environment")
        if environment is not None and (not isinstance(environment, dict) or not all(isinstance(v, str) for v in environment.values())):
            problems.append(f"{where}: environment must map each variable to a quoted string")
        configure = tool.get("configure")
        if configure is not None and (not isinstance(configure, dict) or not all(str(p).startswith("/") and isinstance(c, str) for p, c in configure.items())):
            problems.append(f"{where}: configure must map each absolute path to the file's content")
        for dest, src in (tool.get("repo_files") or {}).items():
            if not str(dest).startswith("/") or not (ROOT / str(src)).is_file():
                problems.append(f"{where}: repo_files must map an absolute path in the image to a file in this repository")
        if "check" in tool and not isinstance(tool["check"], (str, list)):
            problems.append(f"{where}: check must be a command, or a list of them")
    return problems


def pin_archive(name: str, tool: dict) -> tuple[str, list[str]]:
    """Download a tool's archive and return its SHA-256 and what it was checked against."""
    url = fill(tool["url"], tool)
    asset = url.rsplit("/", 1)[-1]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        download(url, work / asset)
        digest = hashlib.sha256((work / asset).read_bytes()).hexdigest()
        checked: list[str] = []
        if tool.get("checksums"):
            download(fill(tool["checksums"], tool), work / "checksums")
            listed = [
                line.split()[0]
                for line in (work / "checksums").read_text(encoding="utf-8").splitlines()
                if len(line.split()) >= 2 and line.split()[-1].lstrip("*") == asset
            ]
            if not listed:
                raise Failure(f"{name}: {asset} is not in the vendor's checksums at {fill(tool['checksums'], tool)}")
            if listed[0].lower() != digest:
                raise Failure(f"{name}: {asset} has SHA-256 {digest}, but the vendor's checksums say {listed[0]}")
            checked.append("the vendor's checksums")
    release = GITHUB_RELEASE.match(url)
    if release:
        # GitHub's own SHA-256 of the asset, taken when it was uploaded, and
        # the vendor's in the release notes where it publishes it there.
        repository, tag, _ = release.groups()
        data = github_api(f"repos/{repository}/releases/tags/{tag}")
        recorded = next((a.get("digest") for a in data.get("assets") or [] if a.get("name") == asset), None)
        if recorded and recorded != f"sha256:{digest}":
            raise Failure(f"{name}: {asset} has SHA-256 {digest}, but GitHub recorded {recorded} when it was uploaded")
        if recorded:
            checked.append("GitHub's digest")
        marker = tool.get("release_notes_sha256")
        if marker:
            noted = re.search(rf"BEGIN SHA {re.escape(str(marker))} -->\s*([0-9a-f]{{64}})", data.get("body") or "")
            if not noted:
                raise Failure(f"{name}: the release notes for {tag} give no SHA-256 for {marker}")
            if noted.group(1) != digest:
                raise Failure(f"{name}: {asset} has SHA-256 {digest}, but the release notes say {noted.group(1)}")
            checked.append("the release notes")
    if not checked:
        print(f"images.py: warning: {name}: nothing to check {asset} against; pinned to its own SHA-256", file=sys.stderr)
    return digest, checked


def pin_python(name: str, tool: dict, catalogue: dict[str, dict]) -> None:
    """Write a python tool's hash-locked requirements, for its interpreter's Python on Linux x86-64."""
    uv = shutil.which("uv")
    if not uv:
        raise Failure("uv is not on PATH")
    python = re.search(r"python(\d+\.\d+)$", python_interpreter(name, catalogue))
    if not python:
        raise Failure(f"{name}: no interpreter to lock for")
    LOCKS.mkdir(parents=True, exist_ok=True)
    lock = LOCKS / f"{name}.txt"
    # Wheels only, because /tmp is noexec on every image, and built for
    # glibc 2.34, RHEL 9's, the oldest of the base images'.
    subprocess.run(
        [uv, "pip", "compile", "-", "--no-config", "--quiet", "--generate-hashes", "--only-binary", ":all:",
         "--python-version", python.group(1), "--python-platform", "x86_64-manylinux_2_34",
         "--custom-compile-command", f"just pin-tools {name}", "--output-file", str(lock)],
        input=f"{tool['package']}=={tool['version']}\n", text=True, check=True, capture_output=True,
    )
    print(f"{name}: locked {tool['package']} {tool['version']} for Python {python.group(1)} in {lock.relative_to(ROOT)}", file=sys.stderr)


# Commands


def cmd_list(_: argparse.Namespace) -> None:
    for name in image_names():
        print(name)


def cmd_targets(args: argparse.Namespace) -> None:
    for target in Image.load(args.image).targets():
        print(target)


def cmd_audit_archive(args: argparse.Namespace) -> None:
    image = Image.load(args.image)
    if not image.audit_archive.is_file():
        raise Failure(f"{image.audit_name} is not fetched: run `just deps {image.name}` first")
    print(image.audit_archive)


def tools_dir() -> Path:
    # Always inside the repository, locally and in CI, so the justfile and the
    # scripts find the tools in the same step that installed them.
    return Path(os.environ.get("TOOLS_DIR") or ROOT / ".tools")


# A download or git fetch that fails retries this many times, waiting longer
# each time, so a network that fails for a moment does not fail a build.
NETWORK_ATTEMPTS = 5


def retry_wait(attempt: int, what: str, error: object) -> None:
    wait = 10 * attempt
    print(f"images.py: {what} failed ({error}); trying again in {wait}s ({attempt}/{NETWORK_ATTEMPTS})", file=sys.stderr)
    time.sleep(wait)


def download(url: str, dest: Path, headers: dict[str, str] | None = None) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "libre-devops-packer-images", **(headers or {})})
    for attempt in range(1, NETWORK_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=120) as response, dest.open("wb") as handle:
                shutil.copyfileobj(response, handle)
            return
        except urllib.error.HTTPError as error:
            # A missing file stays missing; a busy or failing server may not.
            if attempt == NETWORK_ATTEMPTS or (400 <= error.code < 500 and error.code != 429):
                raise
            retry_wait(attempt, f"downloading {url}", error)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            if attempt == NETWORK_ATTEMPTS:
                raise
            retry_wait(attempt, f"downloading {url}", error)


# A release asset on GitHub, whose release the API describes.
GITHUB_RELEASE = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/releases/download/([^/]+)/([^/]+)$")


def github_api(path: str) -> dict:
    """GET from the GitHub API, with GITHUB_TOKEN or GH_TOKEN if set, for the rate limit."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with tempfile.TemporaryDirectory() as tmp:
        download(f"https://api.github.com/{path}", Path(tmp) / "response.json", headers)
        return json.loads((Path(tmp) / "response.json").read_text(encoding="utf-8"))


def verify_hashicorp_signature(sums: Path, signature: Path) -> None:
    """Check the checksums file is signed by HashiCorp's release key."""
    with tempfile.TemporaryDirectory() as home:
        gpg = ["gpg", "--batch", "--no-tty", "--homedir", home]
        subprocess.run([*gpg, "--quiet", "--import", str(ROOT / "keys" / "hashicorp.asc")], check=True, capture_output=True)
        result = subprocess.run([*gpg, "--status-fd", "1", "--verify", str(signature), str(sums)], capture_output=True, text=True)
    # VALIDSIG <signing subkey> ... <primary key fingerprint>
    primaries = [line.split()[-1] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if result.returncode != 0 or HASHICORP_FINGERPRINT not in primaries:
        raise Failure(f"{sums.name}: no valid signature from HashiCorp's key {HASHICORP_FINGERPRINT}\n{result.stderr}")


def cmd_tools(_: argparse.Namespace) -> None:
    version = str(load_yaml(ROOT / "versions.yml")["tools"]["packer"])
    bin_dir = tools_dir() / "bin"
    packer = bin_dir / "packer"
    if packer.is_file():
        current = subprocess.run([str(packer), "version"], capture_output=True, text=True).stdout
        if current.startswith(f"Packer v{version}"):
            finish_tools(bin_dir)
            return

    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine().lower()]
    base = f"https://releases.hashicorp.com/packer/{version}"
    archive = f"packer_{version}_linux_{arch}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        sums, signature = work / "SHA256SUMS", work / "SHA256SUMS.sig"
        download(f"{base}/packer_{version}_SHA256SUMS", sums)
        download(f"{base}/packer_{version}_SHA256SUMS.sig", signature)
        verify_hashicorp_signature(sums, signature)
        expected = next((line.split()[0] for line in sums.read_text().splitlines() if line.endswith(f"  {archive}")), None)
        if not expected:
            raise Failure(f"{archive} is not in HashiCorp's checksums for Packer {version}")
        download(f"{base}/{archive}", work / archive)
        actual = hashlib.sha256((work / archive).read_bytes()).hexdigest()
        if actual != expected:
            raise Failure(f"{archive}: SHA-256 {actual} does not match HashiCorp's {expected}")
        bin_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(work / archive) as bundle:
            bundle.extract("packer", work)
        shutil.move(work / "packer", packer)
        packer.chmod(0o755)
    print(f"Installed Packer {version} (signature and SHA-256 checked)", file=sys.stderr)
    finish_tools(bin_dir)


def finish_tools(bin_dir: Path) -> None:
    print(bin_dir)


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def git_network(*args: str, cwd: Path | None = None, clean: Path | None = None) -> str:
    """A git command that reaches the network (clone or fetch), retried. `clean` is removed before each retry."""
    for attempt in range(1, NETWORK_ATTEMPTS + 1):
        try:
            return git(*args, cwd=cwd)
        except subprocess.CalledProcessError as error:
            if attempt == NETWORK_ATTEMPTS:
                raise
            if clean is not None:
                shutil.rmtree(clean, ignore_errors=True)
            retry_wait(attempt, f"git {args[0]}", (error.stderr or "").strip().splitlines()[-1:] or error)
    raise AssertionError("unreachable")


def cmd_deps(args: argparse.Namespace) -> None:
    for name in args.images or image_names():
        image = Image.load(name)
        fetch_role(image)
        fetch_audit(image)


def role_date(image: Image) -> str:
    """When the pinned role release was committed, as an ISO 8601 timestamp."""
    return git("log", "-1", "--format=%cI", "HEAD", cwd=image.role_dir)


def matching_audit_commit(image: Image) -> tuple[str, str]:
    """The last commit on the audit branch at or before the role release.

    The lockdown teams update the audit content first and release the role
    after, so the head of the audit branch often expects variables the
    released role does not pass yet. The commit that matches a role release is
    the last one before it.
    """
    audit = image.audit
    history = CACHE / "audit" / f"{image.audit_name}.git"
    if history.is_dir():
        git_network("fetch", "--quiet", "--filter=blob:none", "origin", f"+refs/heads/{audit['branch']}:refs/heads/{audit['branch']}", cwd=history)
    else:
        history.parent.mkdir(parents=True, exist_ok=True)
        git_network("clone", "--quiet", "--bare", "--filter=blob:none", "--single-branch", "--branch", audit["branch"], audit["repo"], str(history), clean=history)
    released = role_date(image)
    commit = git("rev-list", "-1", f"--before={released}", f"refs/heads/{audit['branch']}", cwd=history)
    if not commit:
        raise Failure(f"{image.audit_name} has no commit on {audit['branch']} before {image.role_name} {image.role['version']} ({released})")
    return commit, git("log", "-1", "--format=%cs", commit, cwd=history)


def cmd_pin_audit(args: argparse.Namespace) -> None:
    """Pin each image's audit content to the commit that matches its role release."""
    for name in args.images or image_names():
        image = Image.load(name)
        if image.base:
            print(f"{name}: a role image, so it uses {image.base.name}'s audit content", file=sys.stderr)
            continue
        fetch_role(image)
        commit, date = matching_audit_commit(image)
        if commit == image.audit["commit"]:
            print(f"{name}: {image.audit_name} already pinned to {commit[:12]} ({date})", file=sys.stderr)
            continue
        path = image.path / "image.yml"
        text = path.read_text(encoding="utf-8")
        pattern = re.compile(r"(branch:\s*" + re.escape(str(image.audit["branch"])) + r"\s*\n\s*commit:\s*)[0-9a-f]{40}")
        text, count = pattern.subn(lambda m: m.group(1) + commit, text)
        if count != 1:
            raise Failure(f"{path.relative_to(ROOT)}: could not find the audit commit line to update")
        path.write_text(text, encoding="utf-8")
        print(f"{name}: pinned {image.audit_name} to {commit[:12]} ({date}), to match {image.role_name} {image.role['version']}", file=sys.stderr)


def python_lock_current(name: str, tool: dict) -> bool:
    lock = LOCKS / f"{name}.txt"
    return lock.is_file() and bool(
        re.search(rf"^{re.escape(str(tool.get('package')))}=={re.escape(str(tool.get('version')))}\b", lock.read_text(encoding="utf-8"), re.MULTILINE | re.IGNORECASE)
    )


def cmd_pin_tools(args: argparse.Namespace) -> None:
    """Pin each archive tool's SHA-256 and each python tool's hash-locked requirements.

    Only pins that are missing or were made for another version, unless
    --force: a pin changes when its version does, and not otherwise.
    """
    catalogue = load_catalogue()
    for name in args.tools:
        if name not in catalogue:
            raise Failure(f"no tool called {name!r} in tools/tools.yml")
    text = CATALOGUE.read_text(encoding="utf-8")
    for name in args.tools or list(catalogue):
        tool = catalogue[name]
        if tool.get("method") == "archive" and not args.force:
            pin = SHA256_PIN.search(tool_blocks(text)[name])
            if pin and pin.group(2) == str(tool.get("version")):
                print(f"{name}: {tool['version']} already pinned", file=sys.stderr)
                continue
        if tool.get("method") == "python" and not args.force and python_lock_current(name, tool):
            print(f"{name}: {tool['version']} already locked", file=sys.stderr)
            continue
        if tool.get("method") == "archive":
            digest, checked = pin_archive(name, tool)
            block = tool_blocks(text)[name]
            line = f'    sha256: "{digest}"  # {tool["version"]}'
            updated, count = re.subn(r"^    sha256:.*$", lambda _: line, block, count=1, flags=re.MULTILINE)
            if count != 1:
                raise Failure(f"tools/tools.yml {name}: no sha256 line to update")
            if updated != block:
                text = text.replace(block, updated, 1)
                print(f"{name}: pinned {tool['version']} to SHA-256 {digest[:16]}... (matches {' and '.join(checked) or 'nothing else'})", file=sys.stderr)
            else:
                print(f"{name}: {tool['version']} already pinned, and matches {' and '.join(checked) or 'nothing else'}", file=sys.stderr)
        elif tool.get("method") == "python":
            pin_python(name, tool, catalogue)
    CATALOGUE.write_text(text, encoding="utf-8")


def fetch_role(image: Image) -> None:
    role, dest = image.role, image.role_dir
    marker = dest / ".pinned"
    pin = f"{role['version']} {role['commit']}"
    if marker.is_file() and marker.read_text().strip() == pin:
        return
    shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git_network("clone", "--quiet", "--depth", "1", "--branch", str(role["version"]), role["repo"], str(dest), clean=dest)
    head = git("rev-parse", "HEAD", cwd=dest)
    if head != role["commit"]:
        shutil.rmtree(dest)
        raise Failure(f"{image.role_name} tag {role['version']} is now {head}, not the pinned {role['commit']}. Check why before trusting it.")
    marker.write_text(pin + "\n")
    print(f"Fetched {image.role_name} {role['version']} ({head[:12]})", file=sys.stderr)


def fetch_audit(image: Image) -> None:
    audit, archive = image.audit, image.audit_archive
    if archive.is_file():
        return
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        git("init", "--quiet", cwd=work)
        git_network("fetch", "--quiet", "--depth", "1", audit["repo"], audit["commit"], cwd=work)
        head = git("rev-parse", "FETCH_HEAD", cwd=work)
        if head != audit["commit"]:
            raise Failure(f"{image.audit_name}: fetched {head}, not the pinned {audit['commit']}")
        committed, released = git("log", "-1", "--format=%cI", "FETCH_HEAD", cwd=work), role_date(image)
        if datetime.fromisoformat(committed) > datetime.fromisoformat(released):
            raise Failure(
                f"{image.audit_name} {audit['commit'][:12]} ({committed[:10]}) is newer than {image.role_name} "
                f"{image.role['version']} ({released[:10]}), so it can expect variables the role does not pass. "
                f"Run `just pin-audit {image.name}`."
            )
        # The lockdown role unpacks this into /opt and expects /opt/<name>.
        git("archive", "--format=tar.gz", f"--prefix={image.audit_name}/", "-o", str(archive), "FETCH_HEAD", cwd=work)
    print(f"Fetched {image.audit_name} at {audit['commit'][:12]}", file=sys.stderr)


def base_disk(image: Image, target: str, placeholder: bool = False) -> tuple[Path, str]:
    """A role image's starting disk, its base's finished qcow2, and that disk's checksum from the base build."""
    base = image.base
    out = OUTPUT / base.name / target
    disk = out / f"{base.name}.qcow2"
    sums = out / "image.sha256"
    if disk.is_file() and sums.is_file():
        for line in sums.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == disk.name and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                return disk, f"sha256:{parts[0]}"
    if placeholder:
        # For `packer validate`, which needs a value but never reads the disk.
        return disk, "sha256:" + "0" * 64
    raise Failure(f"{image.name} builds on {base.name}, which is not built for {target}: run `just build {base.name} {target}` first")


def cmd_render(args: argparse.Namespace) -> None:
    """Write the hardening vars, the Packer variables and the image record."""
    image = Image.load(args.image)
    if args.target not in image.targets():
        raise Failure(f"{image.name} has no {args.target!r} source (it has: {', '.join(image.targets())})")
    profile = load_profile(image, args.target)
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    hardening_vars = {"hardening_role": image.role_name, "hardening_profile": profile.tag}
    if profile.keep_modules is not None:
        hardening_vars["hardening_filesystem_modules_keep"] = profile.keep_modules
    if profile.firewall_services is not None:
        hardening_vars["hardening_firewall_services"] = profile.firewall_services
    hardening_vars.update({s.var: s.value for s in profile.settings})
    hardening_file = work / "hardening.yml"
    hardening_file.write_text(
        "---\n# Rendered by scripts/images.py from images/{0}/hardening. Do not edit.\n{1}".format(
            image.name, yaml.safe_dump(hardening_vars, sort_keys=False)
        ),
        encoding="utf-8",
    )

    catalogue = load_catalogue()
    tools = [render_tool(name, catalogue) for name in image_tools(image, catalogue)]
    environment: dict[str, str] = {}
    for tool in tools:
        environment |= tool.get("environment") or {}
    tools_file = work / "tools.yml"
    tools_file.write_text(
        "---\n# Rendered by scripts/images.py from tools/tools.yml for {0}. Do not edit.\n{1}".format(
            image.name, yaml.safe_dump({"image_tools": tools, "image_environment": environment}, sort_keys=False)
        ),
        encoding="utf-8",
    )

    if args.ssh_key:
        key = Path(args.ssh_key).resolve()
        packer_vars = {
            "output_directory": str(Path(args.output).resolve()),
            "ssh_private_key_file": str(key),
            "ssh_public_key": key.with_suffix(".pub").read_text().strip(),
            "tools_vars_file": str(tools_file.resolve()),
        }
        if image.base:
            disk, checksum = base_disk(image, args.target, placeholder=args.placeholder_base)
            packer_vars |= {"base_image": str(disk), "base_image_checksum": checksum}
        else:
            packer_vars |= {
                "iso_urls": image.spec["iso"]["urls"],
                "iso_checksum": f"sha256:{image.spec['iso']['sha256']}",
                "hardening_vars_file": str(hardening_file.resolve()),
                "hardening_tags": profile.tag,
            }
        (work / "build.pkrvars.json").write_text(json.dumps(packer_vars, indent=2) + "\n", encoding="utf-8")

    exceptions = [
        {
            "id": e.id,
            "title": e.title,
            "kind": e.kind,
            "risk": e.risk,
            "controls": image_covers(e, image, args.target),
            "decided_on": str(e.decided_on),
            "review_by": str(e.review_by),
        }
        for e in load_registry()
        if e.active and image_covers(e, image, args.target)
    ]
    record: dict = {
        "image": image.name,
        "target": args.target,
        "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": git_head(),
    }
    if image.base:
        base_record = OUTPUT / image.base.name / args.target / "image.json"
        record["base"] = json.loads(base_record.read_text(encoding="utf-8")) if base_record.is_file() else {"image": image.base.name}
    else:
        record["iso"] = image.spec["iso"]
    record["tools"] = [{"name": t["name"], "method": t["method"], "version": t.get("version", "base image repositories")} for t in tools]
    record |= {
        "hardening": {
            "role": {"name": image.role_name, **image.role},
            "audit": {"name": image.audit_name, **image.audit},
            "profile": profile.tag,
            "settings": [s.__dict__ for s in profile.settings],
            "filesystem_modules_kept": profile.keep_modules,
            "firewall_services": profile.firewall_services,
            "exceptions": exceptions,
        },
    }
    (work / "image.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def git_head() -> str | None:
    try:
        commit = git("rev-parse", "HEAD", cwd=ROOT)
    except subprocess.CalledProcessError:
        return None
    dirty = git("status", "--porcelain", cwd=ROOT)
    return f"{commit}{'-dirty' if dirty else ''}"


def cmd_validate(args: argparse.Namespace) -> None:
    on = today()
    entries = load_registry()
    problems = [f"exceptions.yml: {p}" for p in registry_problems(entries, on)]
    problems += catalogue_problems(load_catalogue())
    for name in args.images or image_names():
        image = Image.load(name)
        problems.extend(f"{name}: {p}" for p in validate_image(image, entries))
    for warning in due_soon(entries, on):
        print(f"images.py: warning: {warning}", file=sys.stderr)
    if problems:
        raise Failure("\n".join(problems))
    print("Every image definition, hardening profile and exception is valid.", file=sys.stderr)


def validate_tools(image: Image) -> list[str]:
    tools = image.spec.get("tools")
    if tools is None:
        return []
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        return ["image.yml tools must list tool names from tools/tools.yml"]
    try:
        image_tools(image, load_catalogue())
    except Failure as error:
        return [str(error)]
    return []


def validate_role_image(image: Image) -> list[str]:
    """A role image: a base that is a golden image, tools, and no hardening of its own."""
    problems = []
    spec = image.spec
    name = str(spec.get("base"))
    if name not in image_names():
        return [f"image.yml base {name!r} is not an image"]
    base = Image.load(name)
    if base.base:
        problems.append(f"image.yml base {name} is a role image; build on a golden image")
    for key in ("iso", "hardening"):
        if key in spec:
            problems.append(f"image.yml {key}: a role image takes it from its base, {name}")
    if (image.path / "hardening").exists():
        problems.append(f"hardening/: a role image applies its base's hardening, so it has none of its own")
    for target in image.targets():
        if target not in base.targets():
            problems.append(f"source {target!r}: {name} has no {target!r} target to build on")
    if not spec.get("tools"):
        problems.append("image.yml tools: a role image exists to add tools, so list them")
    return problems + validate_tools(image)


def validate_image(image: Image, entries: list[Entry]) -> list[str]:
    problems = []
    spec = image.spec
    if spec.get("name") != image.name:
        problems.append(f"image.yml name is {spec.get('name')!r}, not the folder name")
    if "base" in spec:
        return problems + validate_role_image(image)
    problems += validate_tools(image)
    iso = spec.get("iso") or {}
    if not iso.get("urls") or not re.fullmatch(r"[0-9a-f]{64}", str(iso.get("sha256", ""))):
        problems.append("image.yml needs iso.urls and a 64 character iso.sha256")
    for key in ("role", "audit"):
        if not re.fullmatch(r"[0-9a-f]{40}", str((spec.get("hardening") or {}).get(key, {}).get("commit", ""))):
            problems.append(f"image.yml hardening.{key}.commit must be a full commit hash")

    targets = image.targets()
    hardening = image.path / "hardening"
    files = sorted(p.stem for p in hardening.glob("*.yml") if p.stem != "common")
    for target in targets:
        if target not in files:
            problems.append(f"source {target!r} has no hardening/{target}.yml")
    for stray in sorted(set(files) - set(targets)):
        problems.append(f"hardening/{stray}.yml matches no Packer source")

    known = role_defaults(image)

    def check_exception(where: str, entry_id: str, target: str | None, control: str | None = None) -> None:
        """An exception a hardening file names must be active and cover this image (and control)."""
        entry = find_entry(entries, entry_id)
        if not entry:
            problems.append(f"{where}: exception {entry_id} is not in exceptions.yml")
            return
        if not entry.active:
            problems.append(f"{where}: exception {entry_id} is {entry.status}")
        # A setting in common.yml applies to every target, so its exception must too.
        covered = entry.controls.get(image.name, []) if target is None else entry.covers(image.name, target)
        if not covered:
            problems.append(f"{where}: exception {entry_id} does not cover {image.name}{'' if target is None else '/' + target}")
        elif control and control not in covered:
            problems.append(f"{where}: exception {entry_id} does not cover control {control} for {image.name}")

    for path in [hardening / "common.yml", *(hardening / f"{t}.yml" for t in targets)]:
        if not path.is_file():
            continue
        target = None if path.stem == "common" else path.stem
        data = load_yaml(path)
        seen = set()
        for entry in data.get("settings") or []:
            var = entry.get("var")
            where = f"{path.relative_to(image.path)} {var}"
            if not var or "value" not in entry:
                problems.append(f"{where}: every setting needs var and value")
                continue
            if var in seen:
                problems.append(f"{where}: set twice")
            seen.add(var)
            if var not in known:
                problems.append(f"{where}: {image.role_name} {image.role['version']} has no such variable")
            setting = Setting(var, entry["value"], squash(entry.get("reason")), path.name, str(entry.get("exception") or ""))
            if SECTION_VAR.match(var) and setting.value is False:
                problems.append(f"{where}: switches off a whole CIS section; switch off single controls, each with an exception")
            if setting.disabled_control and not setting.exception:
                problems.append(f"{where}: switches off CIS {setting.disabled_control}, so it needs `exception:` naming its entry in exceptions.yml")
            if setting.exception:
                check_exception(where, setting.exception, target, setting.disabled_control)
            elif not setting.reason:
                problems.append(f"{where}: no reason given")

        services = data.get("firewall_services")
        if services is not None and (not isinstance(services, list) or not all(isinstance(s, str) and s for s in services)):
            problems.append(f"{path.relative_to(image.path)} firewall_services: must list the firewall service names to allow")

        modules = data.get("filesystem_modules")
        if modules is not None:
            where = f"{path.relative_to(image.path)} filesystem_modules"
            keep = modules.get("keep") if isinstance(modules, dict) else None
            entry_id = str(modules.get("exception") or "") if isinstance(modules, dict) else ""
            if not isinstance(keep, list):
                problems.append(f"{where}: needs keep, the list of filesystem modules to leave loadable")
            if not entry_id:
                problems.append(f"{where}: needs exception, the entry in exceptions.yml that records the modules kept")
            else:
                check_exception(where, entry_id, target)
                entry = find_entry(entries, entry_id)
                allowed = allowed_findings(entry, [image.name]) if entry else None
                if isinstance(keep, list) and sorted(allowed or []) != sorted(map(str, keep)):
                    problems.append(f"{where}: keep {sorted(map(str, keep))} must match {entry_id} findings.allowed {sorted(map(str, allowed or []))}")
    return problems


# Docs


def render_image_readme(image: Image) -> str:
    if image.base:
        return render_role_readme(image)
    spec, role, audit = image.spec, image.role, image.audit
    iso_name = spec["iso"]["urls"][0].rsplit("/", 1)[-1]
    targets = image.targets()
    profile = load_profile(image, targets[0]).tag
    registry = load_registry()
    entries = [e for e in registry if e.active and image_covers(e, image)]

    lines = [
        "<!-- Written by `just docs` from image.yml, hardening/ and ../../exceptions.yml. Edit those, not this file. -->",
        "",
        f"# {image.name}",
        "",
        f"{spec['description']}.",
        "",
    ]
    for note in spec.get("notes") or []:
        lines += [squash(note), ""]
    lines += [
        "## Built from",
        "",
        "Pinned in [`image.yml`](./image.yml).",
        "",
        "| Input | Version | Pinned to |",
        "|---|---|---|",
        f"| Installer ISO | `{iso_name}` | SHA-256 `{spec['iso']['sha256'][:16]}...` |",
        f"| Hardening role | [{image.role_name}]({role['repo']}) `{role['version']}` | commit `{role['commit'][:12]}` |",
        f"| Audit content | [{image.audit_name}]({audit['repo']}) `{audit['branch']}` | commit `{audit['commit'][:12]}` |",
        "",
        f"CIS profile: `{profile}`.",
        "",
        "## Changes to the role's defaults",
        "",
        "From [`hardening/common.yml`](./hardening/common.yml) and each target's file. Everything not listed runs as the role's defaults.",
        "",
        "| Variable | Value | Targets | Reason |",
        "|---|---|---|---|",
    ]
    rows: dict[tuple, dict] = {}
    modules: dict[tuple, list[str]] = {}
    services: dict[tuple, list[str]] = {}
    for target in targets:
        target_profile = load_profile(image, target)
        if target_profile.firewall_services is not None:
            services.setdefault(tuple(target_profile.firewall_services), []).append(target)
        for setting in target_profile.settings:
            key = (setting.var, json.dumps(setting.value), setting.reason, setting.exception)
            rows.setdefault(key, {"setting": setting, "targets": []})["targets"].append(target)
        if target_profile.keep_modules is not None:
            modules.setdefault((tuple(target_profile.keep_modules), target_profile.keep_modules_exception), []).append(target)

    def applies(found: list[str]) -> str:
        return "all" if found == targets else ", ".join(f"`{t}`" for t in found)

    for (var, _, _, _), row in sorted(rows.items(), key=lambda item: natural_key(item[0][0])):
        setting = row["setting"]
        switched = find_entry(registry, setting.exception) if setting.exception else None
        why = f"Switched off: {switched.id}, {cell(switched.title)}." if switched else f"Exception {setting.exception}." if setting.exception else cell(setting.reason)
        lines.append(f"| `{var}` | `{json.dumps(setting.value)}` | {applies(row['targets'])} | {why} |")
    for (keep, entry_id), found in modules.items():
        kept = [f"`{m}`" for m in keep]
        kept_text = " and ".join([", ".join(kept[:-1]), kept[-1]]) if len(kept) > 1 else "".join(kept)
        lines += [
            "",
            "The harden step also blocks every filesystem kernel module the kernel ships, except those mounted, the ones CIS "
            f"counts as standard (ext2, ext3, ext4, xfs and vfat), and the ones this image keeps: {kept_text or 'none'} "
            f"(targets: {applies(found)}; exception {entry_id}).",
        ]
    for allowed, found in services.items():
        lines += [
            "",
            f"The harden step also sets the default firewall zone to allow only {', '.join(f'`{s}`' for s in allowed) or 'nothing'} "
            f"(targets: {applies(found)}).",
        ]
    if image.spec.get("tools"):
        lines += ["", *tools_section(image, "Installed before the harden step, so the lockdown role hardens them with the rest of the system.")]
    lines += ["", *exceptions_section(image, entries)]
    lines += [
        "",
        "## Targets",
        "",
        "| Target | Packer source | Hardening file |",
        "|---|---|---|",
    ]
    for target in targets:
        lines.append(f"| `{target}` | [`{target}.pkr.hcl`](./{target}.pkr.hcl) | [`hardening/{target}.yml`](./hardening/{target}.yml) |")
    lines += ["", f"Build and test it with `just all {image.name} <target>`.", ""]
    return "\n".join(lines)


def cell(text: object) -> str:
    return squash(text).replace("|", "\\|")


def tools_section(image: Image, when: str) -> list[str]:
    catalogue = load_catalogue()
    how = {
        "package": "the base image's signed packages, patched at every build",
        "archive": "release archive, SHA-256 pinned",
        "python": "own Python environment, hash-locked requirements",
        "tenv": "through tenv, HashiCorp's signature checked",
        "directory": "a directory the image makes, owned by root and a group",
    }
    lines = [
        "## Tools",
        "",
        f"From the catalogue in [`tools/tools.yml`](../../tools/tools.yml). {when} The test runs each one as an unprivileged user.",
        "",
        "| Tool | Version | Installed from | What |",
        "|---|---|---|---|",
    ]
    for name in image_tools(image, catalogue):
        tool = catalogue[name]
        version = f"`{tool['version']}`" if "version" in tool else "the distribution's" if tool["method"] == "package" else "none"
        lines.append(f"| `{name}` | {version} | {how[tool['method']]} | {cell(tool.get('description'))} |")
    return lines


def exceptions_section(image: Image, entries: list[Entry]) -> list[str]:
    inherited = f" They include every exception for its base, `{image.base.name}`." if image.base else ""
    lines = [
        "## Exceptions",
        "",
        "The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml)."
        f"{inherited} "
        "The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.",
        "",
        "| ID | Controls | Kind | Risk | Review by | Decision |",
        "|---|---|---|---|---|---|",
    ]
    for entry in entries:
        parts = []
        for name in image.lineage:
            controls = ", ".join(entry.controls.get(name, []))
            for key, scoped in entry.controls.items():
                if key.startswith(f"{name}/"):
                    controls += f"{', ' if controls else ''}{', '.join(scoped)} (`{key.split('/', 1)[1]}` only)"
            if controls:
                parts.append(controls)
        decision = f"**{cell(entry.title)}.** {cell(entry.reason)}"
        if entry.mitigation:
            decision += f" Mitigation: {cell(entry.mitigation)}"
        lines.append(f"| {entry.id} | {'; '.join(parts)} | {entry.kind} | {entry.risk} | {entry.review_by} | {decision} |")
    return lines


def render_role_readme(image: Image) -> str:
    spec, base = image.spec, image.base
    entries = [e for e in load_registry() if e.active and image_covers(e, image)]
    lines = [
        "<!-- Written by `just docs` from image.yml, ../../tools/tools.yml and ../../exceptions.yml. Edit those, not this file. -->",
        "",
        f"# {image.name}",
        "",
        f"{spec['description']}.",
        "",
    ]
    for note in spec.get("notes") or []:
        lines += [squash(note), ""]
    lines += [
        "## Built from",
        "",
        f"The finished [`{base.name}`](../{base.name}) image, so it keeps that image's hardening: "
        f"{image.role_name} `{image.role['version']}`, CIS profile `{load_profile(image, image.targets()[0]).tag}`, "
        f"audited with {image.audit_name} at commit `{image.audit['commit'][:12]}`. "
        "The build boots it as a new VM, patches it, adds the tools below and generalises it again. It does not harden it a second time: "
        "the test audits the result with the same gate, so a tool that weakens the hardening fails the build.",
        "",
        *tools_section(image, "Installed after the base image's hardening, as root, readable by every user."),
        "",
        *exceptions_section(image, entries),
        "",
        "## Targets",
        "",
        "| Target | Packer source |",
        "|---|---|",
    ]
    for target in image.targets():
        lines.append(f"| `{target}` | [`{target}.pkr.hcl`](./{target}.pkr.hcl) |")
    lines += ["", f"Build its base first, then build and test it: `just build {base.name}`, then `just all {image.name}`.", ""]
    return "\n".join(lines)


def cmd_docs(args: argparse.Namespace) -> None:
    stale = []
    for name in image_names():
        image = Image.load(name)
        path = image.path / "README.md"
        text = render_image_readme(image)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(text, encoding="utf-8")
    if stale:
        raise Failure("out of date, run `just docs`: " + ", ".join(stale))


# The audit gate


def result_controls(result: dict) -> list[str]:
    """The CIS controls a goss result checks: its CIS_ID metadata, or the number its title starts with."""
    ids = (result.get("meta") or {}).get("CIS_ID")
    if ids:
        return [str(i) for i in (ids if isinstance(ids, list) else [ids])]
    return [(result.get("title") or result.get("resource-id", "?")).split("|", 1)[0].strip()]


def check_text(result: dict) -> str:
    """A goss title without its control number. Titles read "<control> | <check> | <note>", and
    Markdown tables split on "|", so the parts are joined with colons."""
    parts = [squash(part) for part in (result.get("title") or "").split("|")]
    return ": ".join(parts[1:]) or parts[0]


def cmd_gate(args: argparse.Namespace) -> None:
    """Fail unless every failing audit check is covered by an active, current exception."""
    image = Image.load(args.image)
    if not args.report or not Path(args.report).is_file():
        raise Failure(f"no audit report at {args.report!r}: run `just test {args.image} {args.target}` first")
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    results = report.get("results") or []
    summary = report.get("summary") or {}
    on = today()

    failing: dict[str, list[dict]] = {}
    # Every control the audit ran at least one check for. Some controls have
    # no check in the audit content at all.
    checked: set[str] = set()
    for result in results:
        if result.get("skipped"):
            continue
        for control in result_controls(result):
            checked.add(control)
            if not result.get("successful"):
                failing.setdefault(control, []).append(result)

    entries = [e for e in load_registry() if e.active and image_covers(e, image, args.target)]
    coverage = {control: entry for entry in entries for control in image_covers(entry, image, args.target)}
    # Controls switched off in the role are not audited, so they cannot fail.
    disabled = load_profile(image, args.target).disabled_controls()

    problems = [p for entry in entries for p in entry_problems(entry, on)]
    notes: list[str] = []
    unexpected = sorted((c for c in failing if c not in coverage), key=natural_key)
    for control in unexpected:
        problems.append(f"{control} failed and no exception covers it: fix the image, or record an exception in exceptions.yml")
    for entry in entries:
        for control in image_covers(entry, image, args.target):
            if control in disabled:
                notes.append(f"{entry.id} covers {control}, which the image switches off in the role, so the audit skips it.")
            elif control not in checked:
                notes.append(f"{entry.id} covers {control}, which {image.audit_name} has no check for.")
            elif control not in failing:
                problems.append(f"{entry.id} covers {control}, which passed: take the control out of the entry, or retire the entry")
            # Titles and role tags mark manual controls inconsistently, so this
            # is a prompt to check the classification, not a failure.
            if entry.kind == "manual" and any("manual" not in (r.get("title") or "").lower() for r in failing.get(control, [])):
                notes.append(f"{entry.id} is a manual exception, but the audit's title for {control} does not say Manual: check it is one.")
        if isinstance(entry.findings, dict) and any(c in checked for c in image_covers(entry, image, args.target)):
            # goss prints command output as a quoted string, with \" and \n escaped.
            text = "\n".join(r.get("summary-line") or "" for c in image_covers(entry, image, args.target) for r in failing.get(c, []))
            text = text.replace('\\"', '"').replace("\\n", "\n")
            found = set(re.findall(str(entry.findings.get("pattern")), text))
            allowed = set(allowed_findings(entry, image.lineage) or [])
            if found - allowed:
                problems.append(f"{entry.id} accepts {', '.join(sorted(allowed))}, but the audit also found {', '.join(sorted(found - allowed))}")
            if allowed - found:
                problems.append(f"{entry.id} accepts {', '.join(sorted(allowed - found))}, which the audit no longer finds: take them out")

    lines = [
        f"## Audit: {image.name} ({args.target})",
        "",
        f"{image.audit_name} at `{image.audit['commit'][:12]}`, against the image as built.",
        "",
        "| Checks | Passed | Failed | Skipped |",
        "|---:|---:|---:|---:|",
        "| {0} | {1} | {2} | {3} |".format(
            summary.get("test-count", len(results)),
            summary.get("test-count", len(results)) - summary.get("failed-count", 0) - summary.get("skipped-count", 0),
            summary.get("failed-count", 0),
            summary.get("skipped-count", 0),
        ),
        "",
    ]
    if failing:
        lines += ["| Control | Check | Failed | Exception |", "|---|---|---:|---|"]
        for control in sorted(failing, key=natural_key):
            entry = coverage.get(control)
            status = f"{entry.id}, {entry.kind}, {entry.risk} risk, review by {entry.review_by}: {entry.title}" if entry else "**None**"
            lines.append(f"| {control} | {check_text(failing[control][0])} | {len(failing[control])} | {status} |")
        lines.append("")
    for warning in due_soon(entries, on):
        lines += [f"Warning: {warning}.", ""]
    if notes:
        lines += ["Notes:", "", *(f"- {n}" for n in notes), ""]
    if problems:
        lines += [f"**The gate failed with {len(problems)} problem(s):**", "", *(f"- {p}" for p in problems), ""]
    else:
        lines += ["Every failed check is covered by an exception, and every exception is current and still needed.", ""]

    text = "\n".join(lines)
    Path(args.summary).write_text(text, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)

    if problems:
        for control in unexpected:
            for result in failing[control]:
                print(f"FAILED {result.get('title')}: {(result.get('summary-line') or '').strip()}", file=sys.stderr)
        raise Failure(f"audit gate: {len(problems)} problem(s), listed above")


def cmd_exceptions(_: argparse.Namespace) -> None:
    """List the registry, soonest review first."""
    on = today()
    entries = sorted(load_registry(), key=lambda e: (not e.active, e.review_by or date.max, natural_key(e.id)))
    print(f"{'ID':<7} {'Status':<8} {'Kind':<14} {'Risk':<6} {'Review by':<10} {'Days':>5}  Covers / title")
    for e in entries:
        days = (e.review_by - on).days if e.review_by else ""
        covers = "; ".join(f"{k}: {', '.join(v)}" for k, v in e.controls.items())
        print(f"{e.id:<7} {e.status:<8} {e.kind:<14} {e.risk:<6} {str(e.review_by):<10} {days:>5}  {covers}")
        print(f"{'':<57}{e.title}")


def natural_key(control: str) -> list:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", control)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="list the images").set_defaults(func=cmd_list)

    sub = commands.add_parser("targets", help="list an image's targets (its Packer source types)")
    sub.add_argument("image")
    sub.set_defaults(func=cmd_targets)

    sub = commands.add_parser("audit-archive", help="print the path of an image's fetched audit content")
    sub.add_argument("image")
    sub.set_defaults(func=cmd_audit_archive)

    commands.add_parser("tools", help="install the pinned Packer, checking HashiCorp's signature").set_defaults(func=cmd_tools)

    sub = commands.add_parser("deps", help="fetch the pinned hardening role and audit content")
    sub.add_argument("images", nargs="*")
    sub.set_defaults(func=cmd_deps)

    sub = commands.add_parser("pin-audit", help="pin audit content to the commit that matches the role release")
    sub.add_argument("images", nargs="*")
    sub.set_defaults(func=cmd_pin_audit)

    sub = commands.add_parser("pin-tools", help="pin each archive tool's SHA-256 and lock each python tool's requirements")
    sub.add_argument("tools", nargs="*")
    sub.add_argument("--force", action="store_true", help="pin again even where the pin is for the current version")
    sub.set_defaults(func=cmd_pin_tools)

    sub = commands.add_parser("render", help="write the hardening vars, tool list, Packer variables and image record")
    sub.add_argument("image")
    sub.add_argument("target")
    sub.add_argument("--workdir", required=True, help="where to write the rendered files")
    sub.add_argument("--output", default="", help="the Packer output directory")
    sub.add_argument("--ssh-key", help="the build's private key; omit to render the hardening vars and tool list only")
    sub.add_argument("--placeholder-base", action="store_true", help="for packer validate: allow a role image's base to be unbuilt")
    sub.set_defaults(func=cmd_render)

    sub = commands.add_parser("validate", help="check image definitions, hardening profiles and the exception registry")
    sub.add_argument("images", nargs="*")
    sub.set_defaults(func=cmd_validate)

    sub = commands.add_parser("docs", help="write each image's README from image.yml, hardening/ and exceptions.yml")
    sub.add_argument("--check", action="store_true", help="fail if a README is out of date instead of writing it")
    sub.set_defaults(func=cmd_docs)

    commands.add_parser("exceptions", help="list the exception registry, soonest review first").set_defaults(func=cmd_exceptions)

    sub = commands.add_parser("gate", help="fail unless every failing audit check is covered by a current exception")
    sub.add_argument("image")
    sub.add_argument("target")
    sub.add_argument("report", help="the goss JSON report")
    sub.add_argument("--summary", required=True, help="where to write the Markdown summary")
    sub.set_defaults(func=cmd_gate)

    args = parser.parse_args()
    try:
        args.func(args)
    except Failure as error:
        print(f"images.py: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"images.py: {' '.join(map(str, error.cmd))} failed\n{error.stderr or ''}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
