"""Dependency manifest parsing (Python + npm). No resolution, no network."""

from __future__ import annotations

import configparser
import json
import re
import tomllib
from dataclasses import dataclass

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
DEV_GROUP_RE = re.compile(
    r"(?i)^(dev|develop|development|test|tests|testing|lint|docs?|typing|"
    r"type|mypy|ci|qa|bench|benchmarks?)$"
)
INDEX_OPT_RE = re.compile(
    r"^\s*(-i|--index-url|--extra-index-url|--trusted-host|-f|--find-links)\b"
)

MANIFEST_NAMES = ("pyproject.toml", "setup.cfg", "Pipfile", "package.json")
LOCKFILES = {
    "python": ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"),
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"),
}


class ManifestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Dep:
    ecosystem: str  # python | npm
    name: str  # normalised
    kind: str  # runtime | dev | build
    spec: str
    direct_url: bool
    pinned: bool
    source: str  # manifest path

    def to_json(self) -> dict[str, object]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "kind": self.kind,
            "spec": self.spec,
            "direct_url": self.direct_url,
            "pinned": self.pinned,
            "source": self.source,
        }


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def is_manifest(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return base in MANIFEST_NAMES or bool(
        re.match(r"^(requirements|constraints).*\.(txt|in)$", base)
    )


def lockfile_ecosystem(path: str) -> str | None:
    base = path.rsplit("/", 1)[-1]
    for eco, names in LOCKFILES.items():
        if base in names:
            return eco
    return None


def parse_requirement(line: str, kind: str, source: str) -> Dep | None:
    line = line.split(" #", 1)[0].strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-r", "--requirement", "-c", "--constraint")):
        return None
    editable = line.startswith(("-e ", "-e\t", "--editable"))
    if editable:
        parts = line.split(None, 1)
        line = parts[1] if len(parts) > 1 else ""
    req = line.split(";", 1)[0].strip()
    if not req:
        return None
    if editable or req.startswith(_URL_PREFIXES):
        egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", req)
        name = egg.group(1) if egg else req.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        spec, is_url = req, True
    elif " @ " in req or ("@" in req.split("[", 1)[0] and "://" in req):
        head, spec = req.split("@", 1)
        name, is_url = head.split("[", 1)[0].strip(), True
        spec = spec.strip()
    else:
        m = _NAME_RE.match(req)
        if m is None:
            return None
        name, spec, is_url = m.group(1), m.group(3).strip(), False
    if is_url:
        pinned = bool(re.search(r"@[0-9a-f]{40}\b", spec))
    else:
        pinned = bool(re.fullmatch(r"===?\s*[^\s,*]+", spec))
    return Dep("python", normalize(name), kind, spec, is_url, pinned, source)


_URL_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file:", "./", "../", "/")


def parse_manifest(path: str, text: str | None) -> tuple[list[Dep], list[str]]:
    """Return (deps, index/source options). Raises ManifestError if unparseable."""
    if text is None:
        return [], []
    base = path.rsplit("/", 1)[-1]
    deps: list[Dep] = []
    index_opts: list[str] = []
    try:
        if base == "pyproject.toml":
            data = tomllib.loads(text)
            proj = data.get("project", {})
            for r in proj.get("dependencies", []) or []:
                d = parse_requirement(r, "runtime", path)
                if d:
                    deps.append(d)
            for extra, reqs in (proj.get("optional-dependencies", {}) or {}).items():
                kind = "dev" if DEV_GROUP_RE.match(extra) else "runtime"
                for r in reqs:
                    d = parse_requirement(r, kind, path)
                    if d:
                        deps.append(d)
            for _group, reqs in (data.get("dependency-groups", {}) or {}).items():
                for r in reqs:
                    if isinstance(r, str):
                        d = parse_requirement(r, "dev", path)
                        if d:
                            deps.append(d)
            for r in data.get("build-system", {}).get("requires", []) or []:
                d = parse_requirement(r, "build", path)
                if d:
                    deps.append(d)
            poetry = data.get("tool", {}).get("poetry", {})
            deps += _poetry(poetry.get("dependencies", {}), "runtime", path)
            deps += _poetry(poetry.get("dev-dependencies", {}), "dev", path)
            for _g, gdata in (poetry.get("group", {}) or {}).items():
                deps += _poetry(gdata.get("dependencies", {}), "dev", path)
            uv = data.get("tool", {}).get("uv", {})
            for idx in uv.get("index", []) or []:
                index_opts.append(f"uv index {idx.get('url', '')}")
            for src_name, src in (uv.get("sources", {}) or {}).items():
                index_opts.append(f"uv source {src_name}={json.dumps(src, sort_keys=True)}")
        elif base == "Pipfile":
            data = tomllib.loads(text)
            deps += _poetry(data.get("packages", {}), "runtime", path)
            deps += _poetry(data.get("dev-packages", {}), "dev", path)
            for src in data.get("source", []) or []:
                index_opts.append(f"pipfile source {src.get('url', '')}")
        elif base == "setup.cfg":
            cp = configparser.ConfigParser(interpolation=None)
            cp.read_string(text)
            if cp.has_option("options", "install_requires"):
                for r in cp.get("options", "install_requires").splitlines():
                    d = parse_requirement(r, "runtime", path)
                    if d:
                        deps.append(d)
            if cp.has_section("options.extras_require"):
                for extra, reqs in cp.items("options.extras_require"):
                    kind = "dev" if DEV_GROUP_RE.match(extra) else "runtime"
                    for r in reqs.splitlines():
                        d = parse_requirement(r, kind, path)
                        if d:
                            deps.append(d)
        elif base == "package.json":
            data = json.loads(text)
            for section, kind in (
                ("dependencies", "runtime"),
                ("devDependencies", "dev"),
                ("peerDependencies", "runtime"),
                ("optionalDependencies", "runtime"),
            ):
                for name, spec in (data.get(section, {}) or {}).items():
                    spec = str(spec)
                    url = bool(re.match(r"^(git|https?|file|github:|link:)", spec)) or "/" in spec
                    pinned = bool(re.match(r"^\d+\.\d+\.\d+", spec))
                    deps.append(Dep("npm", name.lower(), kind, spec, url, pinned, path))
        else:  # requirements-style
            kind = "dev" if re.search(r"(?i)(dev|test|lint|doc|ci|typing)", base) else "runtime"
            for raw in text.splitlines():
                if INDEX_OPT_RE.match(raw):
                    index_opts.append(raw.strip())
                    continue
                d = parse_requirement(raw, kind, path)
                if d:
                    deps.append(d)
    except (
        tomllib.TOMLDecodeError,
        json.JSONDecodeError,
        configparser.Error,
        AttributeError,
        TypeError,
    ) as exc:
        raise ManifestError(f"{path}: {exc}") from exc
    return deps, index_opts


def _poetry(table: object, kind: str, path: str) -> list[Dep]:
    out: list[Dep] = []
    if not isinstance(table, dict):
        return out
    for name, spec in table.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            url = any(k in spec for k in ("git", "url", "path"))
            text = json.dumps(spec, sort_keys=True)
            pinned = bool(re.match(r"^=?=?\d", str(spec.get("version", "")))) or "rev" in spec
        else:
            text = str(spec)
            url = False
            pinned = bool(re.match(r"^(==?)?\d+(\.\d+)*$", text))
        out.append(Dep("python", normalize(name), kind, text, url, pinned, path))
    return out
