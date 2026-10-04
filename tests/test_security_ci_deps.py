import pytest

from tests.conftest import POLICY_OK, codes

AUTH = """
import hmac
import subprocess


class Forbidden(Exception):
    pass


def require_admin(user):
    if user.role != "admin":
        raise Forbidden("no")


def delete_user(user, target):
    require_admin(user)
    return target


def check_token(given, expected):
    return hmac.compare_digest(given, expected)


def archive(name):
    return subprocess.run(["tar", "czf", name + ".tgz", "data"], check=True)


def fetch(session, url):
    return session.get(url, verify=True, timeout=5)


def save(store, k, v):
    try:
        store[k] = v
    except KeyError as exc:
        raise RuntimeError("save failed") from exc
"""


def _patch(repo, gate, src: str, extra: dict | None = None):
    repo.commit({"review-gate.yaml": POLICY_OK, "src/app/auth.py": AUTH})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"src/app/auth.py": src, **(extra or {})})
    return gate()


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ("    require_admin(user)\n    return target", "    return target", "auth_check_removed"),
        ('        raise Forbidden("no")', "        pass", "auth_check_removed"),
        ("verify=True", "verify=False", "tls_verification_disabled"),
        (
            "return hmac.compare_digest(given, expected)",
            "return given == expected",
            "constant_time_compare_removed",
        ),
        (
            'subprocess.run(["tar", "czf", name + ".tgz", "data"], check=True)',
            'subprocess.run(f"tar czf {name}.tgz data", shell=True, check=True)',
            "shell_injection_risk",
        ),
        (
            """    except KeyError as exc:
        raise RuntimeError("save failed") from exc""",
            """    except Exception:
        pass""",
            "broad_exception_swallowed",
        ),
    ],
)
def test_security_regressions_block(repo, gate, old, new, code):
    assert AUTH.count(old) == 1
    res = _patch(repo, gate, AUTH.replace(old, new))
    assert code in codes(res)
    assert res.decision.value == "FAIL"


def test_unsafe_deserialization_and_eval(repo, gate):
    src = (
        AUTH + "\n\nimport pickle\n\ndef load(b):\n    return pickle.loads(b)\n\n"
        "def calc(e):\n    return eval(e)\n"
    )
    found = codes(_patch(repo, gate, src))
    assert {"unsafe_deserialization", "dynamic_code_execution"} <= found


def test_preexisting_risky_code_is_not_reported(repo, gate):
    risky = AUTH.replace("verify=True", "verify=False")
    repo.commit({"review-gate.yaml": POLICY_OK, "src/app/auth.py": risky})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"src/app/auth.py": risky + "\n\ndef noop():\n    return None\n"})
    res = gate()
    assert "tls_verification_disabled" not in codes(res)


def test_moving_code_between_files_is_not_new(repo, gate):
    risky = AUTH.replace("verify=True", "verify=False")
    repo.commit({"review-gate.yaml": POLICY_OK, "src/app/auth.py": risky})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"src/app/auth.py": risky})  # no-op commit keeps the pattern
    assert "tls_verification_disabled" not in codes(gate())


def test_secret_is_detected_and_redacted(repo, gate):
    key = "AKIA" + "Q3EXAMPLE7KZ2XYW"
    res = _patch(repo, gate, AUTH, {"config/settings.py": f'KEY = "{key}"\n'})
    f = next(f for f in res.findings if f.code == "secret_introduced")
    assert key not in (f.after or "") and key not in str(res.receipt)


WORKFLOW = """
name: ci
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - run: python -m pytest -q
      - run: bandit -r src
"""


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ("python -m pytest -q", "python -m pytest -q || true", "ci_failure_masked"),
        ("      - run: python -m pytest -q\n", "", "ci_test_step_removed"),
        ("      - run: bandit -r src\n", "", "security_scanner_removed"),
        ("  pull_request:\n", "  pull_request_target:\n", "dangerous_trigger_added"),
        (
            "python -m pytest -q",
            "python -m pytest -q --ignore=tests/test_auth.py",
            "ci_tests_deselected",
        ),
        (
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    if: false\n",
            "ci_job_disabled",
        ),
        (
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    continue-on-error: true\n",
            "ci_failure_masked",
        ),
    ],
)
def test_ci_bypass(repo, gate, old, new, code):
    assert WORKFLOW.count(old) == 1
    repo.commit({"review-gate.yaml": POLICY_OK, ".github/workflows/ci.yml": WORKFLOW})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({".github/workflows/ci.yml": WORKFLOW.replace(old, new)})
    res = gate()
    assert code in codes(res)
    assert res.decision.value == "FAIL"


PYPROJECT = """
[project]
name = "x"
version = "0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
dev = ["pytest>=8"]
"""


@pytest.mark.parametrize(
    ("old", "new", "code", "decision"),
    [
        (
            '"requests==2.31.0"]',
            '"requests==2.31.0", "leftpad-py>=1"]',
            "new_runtime_dependency",
            "FAIL",
        ),
        (
            '"requests==2.31.0"]',
            '"requests==2.31.0", "reqeusts==1.0"]',
            "suspicious_package_name",
            "FAIL",
        ),
        (
            'dev = ["pytest>=8"]',
            'dev = ["pytest @ git+https://github.com/x/pytest@main"]',
            "direct_url_dependency",
            "FAIL",
        ),
        ('dev = ["pytest>=8"]', 'dev = ["pytest>=8", "hypothesis"]', None, "PASS"),
        ('"requests==2.31.0"]', '"requests==2.32.0"]', None, "PASS"),
    ],
)
def test_dependency_policy(repo, gate, old, new, code, decision):
    repo.commit({"review-gate.yaml": POLICY_OK, "pyproject.toml": PYPROJECT})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"pyproject.toml": PYPROJECT.replace(old, new)})
    res = gate()
    if code:
        assert code in codes(res)
    assert res.decision.value == decision


def test_dependency_moved_between_manifests_is_not_new(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": POLICY_OK,
            "requirements.txt": "requests==2.31.0\n",
            "pyproject.toml": PYPROJECT.replace('"requests==2.31.0"', ""),
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit({"pyproject.toml": PYPROJECT}, delete=("requirements.txt",))
    assert "new_runtime_dependency" not in codes(gate())


def test_lockfile_drift(repo, gate):
    repo.commit(
        {
            "review-gate.yaml": "version: 1\ndependency_policy: "
            "{allow_new_runtime_dependencies: true}\n",
            "pyproject.toml": PYPROJECT,
            "uv.lock": "version = 1\n",
        }
    )
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit(
        {
            "pyproject.toml": PYPROJECT.replace(
                '"requests==2.31.0"]', '"requests==2.31.0", "idna==3.7"]'
            )
        }
    )
    res = gate()
    assert "lockfile_not_updated" in codes(res)
    assert res.decision.value == "REVIEW_REQUIRED"


SAVE_BODY = """    try:
        store[k] = v
    except KeyError as exc:
        raise RuntimeError("save failed") from exc"""


@pytest.mark.parametrize(
    "new_body",
    [
        "    try:\n        store[k] = v\n    except Exception:\n        return {}",
        "    with contextlib.suppress(Exception):\n        store[k] = v",
    ],
)
def test_disguised_exception_swallowing(repo, gate, new_body):
    res = _patch(repo, gate, "import contextlib\n" + AUTH.replace(SAVE_BODY, new_body))
    assert "broad_exception_swallowed" in codes(res)


def test_exit_zero_flag_masks_scanner(repo, gate):
    repo.commit({"review-gate.yaml": POLICY_OK, ".github/workflows/ci.yml": WORKFLOW})
    repo.git("checkout", "-q", "-b", "agent")
    repo.commit(
        {".github/workflows/ci.yml": WORKFLOW.replace("bandit -r src", "bandit -r src --exit-zero")}
    )
    assert "ci_failure_masked" in codes(gate())


def test_check_moved_into_helper_is_not_removed(repo, gate):
    # The denial (raise Forbidden) moves into a module-level helper the function calls.
    src = AUTH.replace(
        'def require_admin(user):\n    if user.role != "admin":\n        raise Forbidden("no")',
        "def _deny(msg):\n    raise Forbidden(msg)\n\n\n"
        'def require_admin(user):\n    if user.role != "admin":\n        _deny("no")',
    )
    assert src != AUTH
    res = _patch(repo, gate, src)
    assert "auth_check_removed" not in codes(res)
