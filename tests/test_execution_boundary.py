"""The untrusted-execution boundary: executor selection and container isolation.

Docker-backed tests run only where a working container runtime is present
(set AICRG_REQUIRE_DOCKER=1 to make their absence a failure instead of a skip).
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aicrg.evidence.collect import CollectOptions, build_executor
from aicrg.evidence.executor import (
    ContainerExecutor,
    ContainerSettings,
    ExecRequest,
    ExecutorError,
    LocalExecutor,
)
from aicrg.evidence.workspace import WorkspaceError, safe_write
from aicrg.model import Decision
from aicrg.policy.contract import PolicyError, ReviewContract, parse_contract

PY = sys.executable
IMAGE = os.environ.get("AICRG_TEST_IMAGE", "python:3.12-slim")


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        ok = (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=20, check=False
            ).returncode
            == 0
        )
        if ok:
            subprocess.run(
                ["docker", "image", "inspect", IMAGE], capture_output=True, timeout=20, check=True
            )
        return ok
    except (OSError, subprocess.SubprocessError):
        return False


DOCKER = _docker_ok()
needs_docker = pytest.mark.skipif(
    not DOCKER and not os.environ.get("AICRG_REQUIRE_DOCKER"),
    reason=f"docker with image {IMAGE} not available",
)

CONTAINER_POLICY = f"""
version: 1
execution:
  executor: container
  container:
    image: {IMAGE}
"""


class TestExecutorSelection:
    def test_default_is_local_trusted_mode(self):
        ex = build_executor(ReviewContract(), CollectOptions())
        assert isinstance(ex, LocalExecutor)
        assert ex.describe()["isolation"] == "none"

    def test_operator_cannot_downgrade_container_to_local(self):
        c = parse_contract(CONTAINER_POLICY)
        with pytest.raises(ExecutorError, match="refusing"):
            build_executor(c, CollectOptions(executor="local"))

    def test_operator_may_upgrade_local_to_container(self):
        ex = build_executor(
            ReviewContract(), CollectOptions(executor="container", container_image=IMAGE)
        )
        assert isinstance(ex, ContainerExecutor)

    def test_upgrade_without_image_is_error(self):
        with pytest.raises(ExecutorError):
            build_executor(ReviewContract(), CollectOptions(executor="container"))

    def test_missing_runtime_is_error_never_local_fallback(self, repo, gate, monkeypatch):
        pol = CONTAINER_POLICY.replace("    image:", "    runtime: podman\n    image:") + (
            f"required_checks:\n  - name: t\n    command: [{PY!r}, -c, 'pass']\n"
        )
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        import aicrg.evidence.executor as exmod

        real_which = exmod.shutil.which
        monkeypatch.setattr(
            exmod.shutil,
            "which",
            lambda n, *a, **k: None if n == "podman" else real_which(n, *a, **k),
        )
        res = gate()
        assert res.decision is Decision.ERROR
        assert any(e.stage == "execution" for e in res.errors)
        assert res.checks == []  # nothing ran locally

    @pytest.mark.parametrize(
        "snippet",
        [
            "    user: '0'",
            "    user: '0:0'",
            "    user: root",
            "    network: host",
            "    privileged: true",
            "    volumes: [/var/run/docker.sock:/var/run/docker.sock]",
        ],
    )
    def test_contract_cannot_weaken_isolation(self, snippet):
        with pytest.raises(PolicyError):
            parse_contract(CONTAINER_POLICY + snippet + "\n")

    def test_container_needs_image(self):
        with pytest.raises(PolicyError):
            parse_contract("version: 1\nexecution:\n  executor: container\n")


class TestContainerArgv:
    def _argv(self, tmp_path, **kw):
        host_env = {
            "PATH": "/usr/bin",
            "GITHUB_TOKEN": "ghs_x",
            "AWS_SECRET_ACCESS_KEY": "y",
            "MYVAR": "z",
        }
        ex = ContainerExecutor(ContainerSettings(image=IMAGE, **kw), host_env=host_env)
        monkey = ex._runtime
        ex._runtime = lambda: "/usr/bin/docker"  # type: ignore[method-assign]
        try:
            return ex.runtime_argv(ExecRequest(("python", "-c", "1"), tmp_path, {}, 10), "n")
        finally:
            ex._runtime = monkey  # type: ignore[method-assign]

    def test_hardening_flags(self, tmp_path):
        argv = self._argv(tmp_path)
        joined = " ".join(argv)
        for flag in (
            "--network none",
            "--cap-drop ALL",
            "--read-only",
            "no-new-privileges",
            "--user 65534:65534",
            "--pids-limit",
            "--memory",
        ):
            assert flag in joined
        assert "docker.sock" not in joined
        assert "--privileged" not in joined
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a in ("--mount", "-v", "--volume")]
        assert mounts == [f"type=bind,source={tmp_path.resolve()},target=/workspace"]

    def test_host_environment_is_not_inherited(self, tmp_path):
        argv = self._argv(tmp_path, env_passthrough=("MYVAR",))
        envs = [argv[i + 1] for i, a in enumerate(argv) if a == "--env"]
        names = {e.split("=", 1)[0] for e in envs}
        assert "GITHUB_TOKEN" not in names and "AWS_SECRET_ACCESS_KEY" not in names
        assert "MYVAR" in names  # only explicit, contract-approved names

    def test_trusted_paths_are_mounted_read_only(self, tmp_path):
        (tmp_path / "trusted_tests").mkdir()
        ex = ContainerExecutor(ContainerSettings(image=IMAGE), host_env={})
        ex._runtime = lambda: "/usr/bin/docker"  # type: ignore[method-assign]
        argv = ex.runtime_argv(
            ExecRequest(("python",), tmp_path, {}, 10, readonly=("trusted_tests",)), "n"
        )
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
        assert (
            f"type=bind,source={(tmp_path / 'trusted_tests').resolve()},"
            "target=/workspace/trusted_tests,readonly"
        ) in mounts
        for bad in ("../x", "a,b", "missing"):
            with pytest.raises(ExecutorError):
                ex.runtime_argv(ExecRequest(("python",), tmp_path, {}, 10, readonly=(bad,)), "n")

    def test_network_needs_explicit_opt_in(self, tmp_path):
        assert "--network bridge" in " ".join(self._argv(tmp_path, network="enabled"))

    def test_refuses_to_mount_root_or_home(self):
        ex = ContainerExecutor(ContainerSettings(image=IMAGE), host_env={})
        ex._runtime = lambda: "/usr/bin/docker"  # type: ignore[method-assign]
        for p in (Path("/"), Path.home()):
            with pytest.raises(ExecutorError):
                ex.runtime_argv(ExecRequest(("x",), p, {}, 1), "n")


def test_safe_write_never_follows_symlinks(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (ws / "d").symlink_to(outside)
    (ws / "f").symlink_to(outside / "target")
    safe_write(ws, "d/x.py", b"trusted")
    safe_write(ws, "f", b"trusted")
    assert list(outside.iterdir()) == []
    assert (ws / "d" / "x.py").read_bytes() == b"trusted" and not (ws / "d").is_symlink()
    for bad in ("../x", "/abs", ".git/hooks/pre-commit"):
        with pytest.raises(WorkspaceError):
            safe_write(ws, bad, b"x")


@needs_docker
class TestRealContainerIsolation:
    """Adversarial checks against a real container: what can hostile check code reach?"""

    PROBE = r"""
import json, os, socket, pathlib
out = {"uid": os.getuid()}
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3); out["net"] = "open"
except OSError as e:
    out["net"] = "blocked"
out["env_secret"] = os.environ.get("AICRG_TEST_SECRET_TOKEN")
out["home_visible"] = os.path.exists(HOME)
out["sock"] = os.path.exists("/var/run/docker.sock")
try:
    open("/etc/evil", "w"); out["rootfs"] = "writable"
except OSError:
    out["rootfs"] = "read-only"
pathlib.Path("result.json").write_text(json.dumps(out))
"""

    def test_hostile_check_is_contained(self, repo, gate, monkeypatch):
        probe = self.PROBE.replace("HOME", repr(str(repo.root)))
        pol = CONTAINER_POLICY + (
            "required_checks:\n  - name: probe\n    command: [python, probe.py]\n"
            "    report: {format: json, path: out.json}\n"
        )
        wrap = probe + (
            "\nimport json, pathlib\nr = json.loads(pathlib.Path('result.json').read_text())\n"
            "pathlib.Path('out.json').write_text(json.dumps({'schema': 'aicrg.evidence/v1', "
            "'status': 'findings', 'findings': [{'id': json.dumps(r, sort_keys=True)}]}))\n"
        )
        repo.commit({"review-gate.yaml": pol, "probe.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"probe.py": wrap})
        monkeypatch.setenv("AICRG_TEST_SECRET_TOKEN", "s3cret")
        res = gate()
        import json

        check = res.receipt["checks"][0]
        assert res.receipt["execution"]["executor"] == "container"
        observed = json.loads(check["report"]["items"][0]["identity"])
        assert observed == {
            "uid": 65534,
            "net": "blocked",
            "env_secret": None,
            "home_visible": False,
            "sock": False,
            "rootfs": "read-only",
        }

    def test_container_timeout_is_error_and_container_is_killed(self, repo, gate):
        pol = CONTAINER_POLICY + (
            "required_checks:\n  - name: hang\n    command: [python, -c, 'import time; time.sleep(60)']\n"
            "    timeout_seconds: 3\n"
        )
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        res = gate()
        assert res.decision is Decision.ERROR
        assert res.checks[0].provider_status == "TIMEOUT"
        left = subprocess.run(
            ["docker", "ps", "-q", "--filter", "name=aicrg-"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        assert left == ""

    def test_container_workspace_has_no_git_link_to_host_repo(self, repo, gate):
        pol = CONTAINER_POLICY + (
            "required_checks:\n  - name: nogit\n"
            "    command: [python, -c, 'import os, sys; sys.exit(1 if os.path.exists(\".git\") else 0)']\n"
        )
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        res = gate()
        assert res.decision is Decision.PASS, res.receipt["reasons"]

    def test_failing_check_in_container_is_fail(self, repo, gate):
        pol = CONTAINER_POLICY + (
            "required_checks:\n  - name: t\n    command: [python, -c, 'import a; assert a.x == 1']\n"
        )
        repo.commit({"review-gate.yaml": pol, "a.py": "x = 1\n"})
        repo.git("checkout", "-q", "-b", "agent")
        repo.commit({"a.py": "x = 2\n"})
        res = gate()
        assert res.decision is Decision.FAIL
        assert res.receipt["execution"]["image_id"]
