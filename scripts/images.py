#!/usr/bin/env python3
"""Helpers for the Libre DevOps Packer images.

Every pinned input lives in versions.yml (tools) or images/<name>/image.yml
(ISO, hardening role, audit content), every hardening setting in
images/<name>/hardening/, and every CIS control an image does not meet in the
exception registry, exceptions.yml. This script is the only reader of those
files, so the justfile, the build and test scripts and CI always agree on them.

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
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
IMAGES = ROOT / "images"
CACHE = ROOT / ".cache"
REGISTRY = ROOT / "exceptions.yml"

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
    def role(self) -> dict:
        return self.spec["hardening"]["role"]

    @property
    def audit(self) -> dict:
        return self.spec["hardening"]["audit"]

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
    """The CIS profile tag and the merged settings for one target."""
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


def allowed_findings(entry: Entry, image: str) -> list[str] | None:
    """The findings an entry accepts for an image: one list for all, or a list per image."""
    if not isinstance(entry.findings, dict):
        return None
    allowed = entry.findings.get("allowed")
    if isinstance(allowed, dict):
        allowed = allowed.get(image)
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
    return problems


def find_entry(entries: list[Entry], entry_id: str) -> Entry | None:
    return next((e for e in entries if e.id == entry_id), None)


def due_soon(entries: list[Entry], on: date) -> list[str]:
    return [
        f"{e.id} ({e.title}) is due for review on {e.review_by}"
        for e in entries
        if e.active and e.review_by and 0 <= (e.review_by - on).days <= REVIEW_WARNING_DAYS
    ]


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


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "libre-devops-packer-images"})
    with urllib.request.urlopen(request, timeout=120) as response, dest.open("wb") as handle:
        shutil.copyfileobj(response, handle)


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
        git("fetch", "--quiet", "--filter=blob:none", "origin", f"+refs/heads/{audit['branch']}:refs/heads/{audit['branch']}", cwd=history)
    else:
        history.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--quiet", "--bare", "--filter=blob:none", "--single-branch", "--branch", audit["branch"], audit["repo"], str(history))
    released = role_date(image)
    commit = git("rev-list", "-1", f"--before={released}", f"refs/heads/{audit['branch']}", cwd=history)
    if not commit:
        raise Failure(f"{image.audit_name} has no commit on {audit['branch']} before {image.role_name} {image.role['version']} ({released})")
    return commit, git("log", "-1", "--format=%cs", commit, cwd=history)


def cmd_pin_audit(args: argparse.Namespace) -> None:
    """Pin each image's audit content to the commit that matches its role release."""
    for name in args.images or image_names():
        image = Image.load(name)
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


def fetch_role(image: Image) -> None:
    role, dest = image.role, image.role_dir
    marker = dest / ".pinned"
    pin = f"{role['version']} {role['commit']}"
    if marker.is_file() and marker.read_text().strip() == pin:
        return
    shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git("clone", "--quiet", "--depth", "1", "--branch", str(role["version"]), role["repo"], str(dest))
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
        git("fetch", "--quiet", "--depth", "1", audit["repo"], audit["commit"], cwd=work)
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

    if args.ssh_key:
        key = Path(args.ssh_key).resolve()
        packer_vars = {
            "iso_urls": image.spec["iso"]["urls"],
            "iso_checksum": f"sha256:{image.spec['iso']['sha256']}",
            "output_directory": str(Path(args.output).resolve()),
            "ssh_private_key_file": str(key),
            "ssh_public_key": key.with_suffix(".pub").read_text().strip(),
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
            "controls": e.covers(image.name, args.target),
            "decided_on": str(e.decided_on),
            "review_by": str(e.review_by),
        }
        for e in load_registry()
        if e.active and e.covers(image.name, args.target)
    ]
    record = {
        "image": image.name,
        "target": args.target,
        "built": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": git_head(),
        "iso": image.spec["iso"],
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
    for name in args.images or image_names():
        image = Image.load(name)
        problems.extend(f"{name}: {p}" for p in validate_image(image, entries))
    for warning in due_soon(entries, on):
        print(f"images.py: warning: {warning}", file=sys.stderr)
    if problems:
        raise Failure("\n".join(problems))
    print("Every image definition, hardening profile and exception is valid.", file=sys.stderr)


def validate_image(image: Image, entries: list[Entry]) -> list[str]:
    problems = []
    spec = image.spec
    if spec.get("name") != image.name:
        problems.append(f"image.yml name is {spec.get('name')!r}, not the folder name")
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
                allowed = allowed_findings(entry, image.name) if entry else None
                if isinstance(keep, list) and sorted(allowed or []) != sorted(map(str, keep)):
                    problems.append(f"{where}: keep {sorted(map(str, keep))} must match {entry_id} findings.allowed {sorted(map(str, allowed or []))}")
    return problems


# Docs


def render_image_readme(image: Image) -> str:
    spec, role, audit = image.spec, image.role, image.audit
    iso_name = spec["iso"]["urls"][0].rsplit("/", 1)[-1]
    targets = image.targets()
    profile = load_profile(image, targets[0]).tag
    entries = [e for e in load_registry() if e.active and e.covers(image.name)]

    def cell(text: object) -> str:
        return squash(text).replace("|", "\\|")

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
        why = f"Exception {setting.exception}." if setting.exception else cell(setting.reason)
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
    lines += [
        "",
        "## Exceptions",
        "",
        "The CIS controls this image does not meet, from the registry in [`exceptions.yml`](../../exceptions.yml). "
        "The test fails the build on any other audit failure, on an exception whose control now passes, and on one past its review date.",
        "",
        "| ID | Controls | Kind | Risk | Review by | Decision |",
        "|---|---|---|---|---|---|",
    ]
    for entry in entries:
        controls = ", ".join(entry.controls.get(image.name, []))
        for key, scoped in entry.controls.items():
            if key.startswith(f"{image.name}/"):
                controls += f"{', ' if controls else ''}{', '.join(scoped)} (`{key.split('/', 1)[1]}` only)"
        decision = f"**{cell(entry.title)}.** {cell(entry.reason)}"
        if entry.mitigation:
            decision += f" Mitigation: {cell(entry.mitigation)}"
        lines.append(f"| {entry.id} | {controls} | {entry.kind} | {entry.risk} | {entry.review_by} | {decision} |")
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

    entries = [e for e in load_registry() if e.active and e.covers(image.name, args.target)]
    coverage = {control: entry for entry in entries for control in entry.covers(image.name, args.target)}
    # Controls switched off in the role are not audited, so they cannot fail.
    disabled = load_profile(image, args.target).disabled_controls()

    problems = [p for entry in entries for p in entry_problems(entry, on)]
    notes: list[str] = []
    unexpected = sorted((c for c in failing if c not in coverage), key=natural_key)
    for control in unexpected:
        problems.append(f"{control} failed and no exception covers it: fix the image, or record an exception in exceptions.yml")
    for entry in entries:
        for control in entry.covers(image.name, args.target):
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
        if isinstance(entry.findings, dict) and any(c in checked for c in entry.covers(image.name, args.target)):
            # goss prints command output as a quoted string, with \" and \n escaped.
            text = "\n".join(r.get("summary-line") or "" for c in entry.covers(image.name, args.target) for r in failing.get(c, []))
            text = text.replace('\\"', '"').replace("\\n", "\n")
            found = set(re.findall(str(entry.findings.get("pattern")), text))
            allowed = set(allowed_findings(entry, image.name) or [])
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

    sub = commands.add_parser("render", help="write the hardening vars, Packer variables and image record")
    sub.add_argument("image")
    sub.add_argument("target")
    sub.add_argument("--workdir", required=True, help="where to write the rendered files")
    sub.add_argument("--output", default="", help="the Packer output directory")
    sub.add_argument("--ssh-key", help="the build's private key; omit to render the hardening vars only")
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
