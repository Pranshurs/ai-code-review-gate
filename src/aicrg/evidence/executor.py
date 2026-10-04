"""Where evidence commands run: the untrusted-execution boundary.

Every evidence command executes code from the patch (or, for differential and
trusted evidence, from the base) and must be treated as hostile.

``LocalExecutor``
    Runs the command as a child process of the gate, with the gate's user,
    filesystem and network. Credential-looking environment variables are
    removed, stdin is closed, the process group is killed on timeout. This is
    **trusted-code mode**: it makes no sandbox claim.

``ContainerExecutor``
    Runs the command in a fresh container (Docker or Podman) built from a
    contract-pinned image:

    * unprivileged numeric user, all capabilities dropped, ``no-new-privileges``;
    * read-only root filesystem, a size-limited ``/tmp`` tmpfs;
    * only the throwaway workspace is mounted; no host home, no credential
      directories, never the container runtime socket;
    * the host environment is **not** inherited: only ``HOME``, a few fixed
      variables and the contract's explicit ``env_passthrough`` names;
    * network disabled (``--network none``) unless the contract opts in;
    * CPU, memory, PID and wall-clock limits.

    A container is isolation, not a proof: a kernel or runtime escape defeats
    it. See docs/EXECUTION_SECURITY.md.

The argv passed to the runtime is built entirely here. The contract can choose
values for a fixed set of options; it cannot add arbitrary runtime flags
(``--privileged``, extra mounts, ``--pid host`` ...).
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

# Exit statuses the Docker/Podman CLI uses for its own failures (not the command's).
RUNTIME_ERROR_CODES = frozenset({125})
CONTAINER_WORKDIR = "/workspace"
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")
_DIGEST_PINNED_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_USER_RE = re.compile(r"^[1-9][0-9]{0,9}(:[1-9][0-9]{0,9})?$")


class ExecutorError(RuntimeError):
    """The executor cannot run anything (misconfigured or unavailable). Maps to ERROR."""


@dataclass(frozen=True, slots=True)
class ExecRequest:
    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str]
    timeout_seconds: int
    readonly: tuple[str, ...] = ()  # workspace-relative paths mounted read-only (container)
    readonly_workspace: bool = False  # mount the whole workspace read-only (container)
    writable: tuple[str, ...] = ()  # with readonly_workspace: the only writable subdirectories


@dataclass(frozen=True, slots=True)
class ExecOutcome:
    returncode: int | None
    output: bytes
    timed_out: bool = False
    start_error: str | None = None  # the command never ran; always ERROR


class Executor(Protocol):
    name: str

    def describe(self) -> dict[str, object]: ...

    def prepare(self) -> None: ...

    def run(self, req: ExecRequest) -> ExecOutcome: ...

    def tool_version(self, argv: tuple[str, ...], cwd: Path, env: dict[str, str]) -> str | None: ...

    def workspace_ready(self, path: Path) -> None: ...


def _version_probe(argv: tuple[str, ...]) -> list[str]:
    if len(argv) >= 3 and Path(argv[0]).name.startswith("python") and argv[1] == "-m":
        return [*argv[:3], "--version"]
    return [argv[0], "--version"]


def _drain(proc: subprocess.Popen[bytes]) -> bytes:
    """Collect what is left after a kill without waiting forever.

    A descendant that escaped the process group can hold the pipe open; the
    timeout must still be honoured, so the wait is bounded and the pipe closed.
    """
    try:
        out, _ = proc.communicate(timeout=5)
        return out or b""
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        if proc.stdout is not None:
            proc.stdout.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        return b""


def _first_line(out: bytes) -> str | None:
    lines = out.decode("utf-8", "replace").strip().splitlines()
    return lines[0][:200] if lines else None


class LocalExecutor:
    """Trusted-code mode. No isolation beyond environment filtering and timeouts."""

    name = "local"

    def describe(self) -> dict[str, object]:
        return {
            "executor": "local",
            "isolation": "none",
            "note": "trusted-code mode: commands run with the gate's user, filesystem and network",
        }

    def prepare(self) -> None:
        return None

    def workspace_ready(self, path: Path) -> None:
        return None

    def run(self, req: ExecRequest) -> ExecOutcome:
        # A private temp dir per run (hygiene): evidence does not share the host's temp
        # state, e.g. pytest's per-user basetemp, which concurrent pytest sessions prune.
        tmp = tempfile.mkdtemp(prefix="aicrg-tmp-")
        try:
            env = {**req.env, "TMPDIR": tmp, "TEMP": tmp, "TMP": tmp}
            return self._run(req, env)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _run(self, req: ExecRequest, env: dict[str, str]) -> ExecOutcome:
        argv = req.argv
        exe = shutil.which(argv[0], path=env.get("PATH")) if "/" not in argv[0] else argv[0]
        if exe is None:
            return ExecOutcome(None, b"", start_error=f"executable not found: {argv[0]}")
        try:
            proc = subprocess.Popen(
                list(argv),
                cwd=req.cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as exc:
            return ExecOutcome(None, b"", start_error=f"could not start: {exc}")
        try:
            out, _ = proc.communicate(timeout=req.timeout_seconds)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            return ExecOutcome(proc.returncode, _drain(proc), timed_out=True)
        return ExecOutcome(proc.returncode, out)

    def tool_version(self, argv: tuple[str, ...], cwd: Path, env: dict[str, str]) -> str | None:
        try:
            proc = subprocess.run(
                _version_probe(argv),
                cwd=cwd,
                env=env,
                capture_output=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return _first_line(proc.stdout or proc.stderr) if proc.returncode == 0 else None


@dataclass(frozen=True, slots=True)
class ContainerSettings:
    image: str
    runtime: str = "docker"
    network: str = "none"  # "none" or "enabled" (explicit opt-in)
    cpus: float = 2.0
    memory_mb: int = 2048
    pids_limit: int = 512
    tmpfs_mb: int = 512
    user: str = "65534:65534"
    env_passthrough: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not _IMAGE_RE.match(self.image):
            raise ExecutorError(f"invalid container image reference {self.image!r}")
        if self.runtime not in ("docker", "podman"):
            raise ExecutorError(f"unsupported container runtime {self.runtime!r}")
        if self.network not in ("none", "enabled"):
            raise ExecutorError(
                f"container network must be 'none' or 'enabled', got {self.network!r}"
            )
        if not _USER_RE.match(self.user):
            # Numeric, non-root only: a name could resolve to root inside the image.
            raise ExecutorError(
                f"container user must be numeric uid[:gid] and not 0: {self.user!r}"
            )

    @property
    def digest_pinned(self) -> bool:
        return bool(_DIGEST_PINNED_RE.search(self.image))


# Variables always set inside the container. Nothing else from the host is inherited.
_CONTAINER_FIXED_ENV = {
    "HOME": "/tmp",  # noqa: S108 - container-private tmpfs  # nosec B108
    "TMPDIR": "/tmp",  # noqa: S108 - container-private tmpfs  # nosec B108
    "PYTHONDONTWRITEBYTECODE": "1",
    "AICRG_EVIDENCE": "1",
    "LC_ALL": "C.UTF-8",
}


class ContainerExecutor:
    name = "container"

    def __init__(
        self,
        settings: ContainerSettings,
        *,
        host_env: dict[str, str] | None = None,
        runner: type[subprocess.Popen[bytes]] = subprocess.Popen,
    ) -> None:
        settings.validate()
        self.settings = settings
        self._host_env = dict(os.environ if host_env is None else host_env)
        self._popen = runner
        self.image_id: str | None = None
        self.runtime_version: str | None = None

    # -------------------------------------------------------------- set-up

    def _runtime(self) -> str:
        exe = shutil.which(self.settings.runtime)
        if exe is None:
            raise ExecutorError(
                f"container runtime {self.settings.runtime!r} not found; the contract requires "
                "container execution and the gate never falls back to local execution"
            )
        return exe

    def _cli(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                [self._runtime(), *args],
                capture_output=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExecutorError(f"{self.settings.runtime} {args[0]} failed: {exc}") from exc

    def prepare(self) -> None:
        ver = self._cli("version", "--format", "{{.Server.Version}}", timeout=30)
        if ver.returncode != 0:
            raise ExecutorError(
                f"container runtime unavailable: {ver.stderr.decode('utf-8', 'replace').strip()}"
            )
        self.runtime_version = _first_line(ver.stdout)
        img = self.settings.image
        if self._cli("image", "inspect", img, timeout=60).returncode != 0:
            pulled = self._cli("pull", "--quiet", img, timeout=900)
            if pulled.returncode != 0:
                raise ExecutorError(
                    f"cannot pull image {img}: {pulled.stderr.decode('utf-8', 'replace').strip()}"
                )
        ins = self._cli("image", "inspect", "--format", "{{.Id}}", img, timeout=60)
        if ins.returncode != 0:
            raise ExecutorError(f"cannot inspect image {img}")
        self.image_id = _first_line(ins.stdout)

    def workspace_ready(self, path: Path) -> None:
        """Let the unprivileged container user write inside the throwaway workspace."""
        for root, dirs, files in os.walk(path):
            for name in (*dirs, *files):
                p = os.path.join(root, name)
                if not os.path.islink(p):
                    exe_bits = os.stat(p).st_mode & 0o111
                    mode = 0o777 if os.path.isdir(p) else 0o666 | exe_bits
                    os.chmod(p, mode)  # throwaway workspace; see below
        # The workspace is a throwaway copy inside a 0700 mkdtemp parent.
        os.chmod(path, 0o777)  # noqa: S103 - throwaway, 0700 parent  # nosec B103

    def describe(self) -> dict[str, object]:
        s = self.settings
        return {
            "executor": "container",
            "isolation": "container",
            "runtime": s.runtime,
            "runtime_version": self.runtime_version,
            "image": s.image,
            "image_id": self.image_id,
            "image_digest_pinned": s.digest_pinned,
            "network": s.network,
            "user": s.user,
            "cpus": s.cpus,
            "memory_mb": s.memory_mb,
            "pids_limit": s.pids_limit,
            "read_only_rootfs": True,
            "capabilities": "all dropped",
            "host_env_inherited": False,
            "env_passthrough": list(s.env_passthrough),
            "note": "container isolation, not a guarantee against kernel/runtime escape",
        }

    # -------------------------------------------------------------- execution

    def container_env(self) -> dict[str, str]:
        env = dict(_CONTAINER_FIXED_ENV)
        for name in self.settings.env_passthrough:
            if name in self._host_env and name not in env:
                env[name] = self._host_env[name]
        return env

    def runtime_argv(self, req: ExecRequest, name: str) -> list[str]:
        s = self.settings
        ws = req.cwd.resolve()
        if str(ws) in ("/", str(Path.home().resolve())) or not ws.is_dir():
            raise ExecutorError(f"refusing to mount {ws} into the evidence container")
        argv = [
            self._runtime(),
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none" if s.network == "none" else "bridge",
            "--user",
            s.user,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,size={s.tmpfs_mb}m",  # noqa: S108  # nosec B108
            "--pids-limit",
            str(s.pids_limit),
            "--memory",
            f"{s.memory_mb}m",
            "--memory-swap",
            f"{s.memory_mb}m",
            "--cpus",
            str(s.cpus),
            "--mount",
            f"type=bind,source={ws},target={CONTAINER_WORKDIR}"
            + (",readonly" if req.readonly_workspace else ""),
        ]
        for rel in req.writable:
            src = (ws / rel).resolve()
            if "," in rel or "=" in rel or not src.is_relative_to(ws) or not src.is_dir():
                raise ExecutorError(f"writable path {rel!r} is not a directory in the workspace")
            argv += ["--mount", f"type=bind,source={src},target={CONTAINER_WORKDIR}/{rel}"]
        for rel in () if req.readonly_workspace else req.readonly:
            src = (ws / rel).resolve()
            if "," in rel or "=" in rel or not src.is_relative_to(ws) or not src.exists():
                raise ExecutorError(f"read-only path {rel!r} is not inside the workspace")
            argv += [
                "--mount",
                f"type=bind,source={src},target={CONTAINER_WORKDIR}/{rel},readonly",
            ]
        argv += [
            "--workdir",
            CONTAINER_WORKDIR,
            "--stop-timeout",
            "1",
        ]
        for k, v in sorted(self.container_env().items()):
            argv += ["--env", f"{k}={v}"]
        argv += ["--entrypoint", req.argv[0], s.image, *req.argv[1:]]
        return argv

    def run(self, req: ExecRequest) -> ExecOutcome:
        name = f"aicrg-{uuid.uuid4().hex[:16]}"
        try:
            argv = self.runtime_argv(req, name)
        except ExecutorError as exc:
            return ExecOutcome(None, b"", start_error=str(exc))
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={"PATH": self._host_env.get("PATH", os.defpath)},
                start_new_session=True,
            )
        except OSError as exc:
            return ExecOutcome(None, b"", start_error=f"could not start container: {exc}")
        try:
            out, _ = proc.communicate(timeout=req.timeout_seconds)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ExecutorError):
                self._cli("kill", name, timeout=30)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            return ExecOutcome(proc.returncode, _drain(proc), timed_out=True)
        if proc.returncode in RUNTIME_ERROR_CODES:
            return ExecOutcome(
                proc.returncode,
                out,
                start_error=f"container runtime error (exit {proc.returncode}): "
                + out.decode("utf-8", "replace").strip()[-300:],
            )
        return ExecOutcome(proc.returncode, out)

    def tool_version(self, argv: tuple[str, ...], cwd: Path, env: dict[str, str]) -> str | None:
        res = self.run(ExecRequest(tuple(_version_probe(argv)), cwd, env, 60))
        if res.start_error or res.timed_out or res.returncode != 0:
            return None
        return _first_line(res.output)
