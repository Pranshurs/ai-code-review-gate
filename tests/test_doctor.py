"""`aicrg doctor`: detect ways a pull request could disable its own gate."""

import textwrap
from pathlib import Path

import pytest

from aicrg.cli import main
from aicrg.doctor import Report, github_checks, static_checks

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

GOOD_WF = f"""
name: gate
on:
  pull_request:
permissions:
  contents: read
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
        with:
          persist-credentials: false
      - run: aicrg check --base "$BASE" --head "$HEAD"
"""

GOOD_POLICY = """
version: 1
protected_paths: [./review-gate.yaml]
review_required_surfaces: [ci]
required_checks:
  - name: t
    command: pytest
"""


def _repo(tmp_path: Path, wf: str = GOOD_WF, policy: str | None = GOOD_POLICY) -> Path:
    root = tmp_path / "r"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "gate.yml").write_text(textwrap.dedent(wf))
    if policy is not None:
        (root / "review-gate.yaml").write_text(policy)
    return root


def _status(rep: Report, cid: str) -> set[str]:
    return {c.status for c in rep.checks if c.id == cid}


def test_good_setup_has_no_failures(tmp_path):
    rep = static_checks(_repo(tmp_path))
    assert rep.verdict() == "PASS", [c.to_json() for c in rep.checks if c.status != "PASS"]


def test_missing_gate_workflow_fails(tmp_path):
    rep = static_checks(_repo(tmp_path, GOOD_WF.replace("aicrg check", "pytest")))
    assert _status(rep, "gate-present") == {"FAIL"}
    assert rep.verdict() == "FAIL"


@pytest.mark.parametrize(
    "mutation",
    [
        (
            '- run: aicrg check --base "$BASE" --head "$HEAD"',
            '- run: aicrg check --base "$BASE" || true',
        ),
        ("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    continue-on-error: true"),
        ("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    if: false"),
        ('--head "$HEAD"', '--head "$HEAD" --policy-from file --policy review-gate.yaml'),
    ],
)
def test_masked_or_self_policy_gate_fails(tmp_path, mutation):
    rep = static_checks(_repo(tmp_path, GOOD_WF.replace(*mutation)))
    assert _status(rep, "gate-not-masked") == {"FAIL"}, [c.to_json() for c in rep.checks]


def test_pwn_request_pattern_fails(tmp_path):
    wf = GOOD_WF.replace("  pull_request:", "  pull_request_target:").replace(
        "          persist-credentials: false",
        "          persist-credentials: false\n          ref: ${{ github.event.pull_request.head.sha }}",
    )
    rep = static_checks(_repo(tmp_path, wf))
    assert "FAIL" in _status(rep, "dangerous-trigger")
    assert _status(rep, "gate-trigger") == {"FAIL"}


def test_broad_token_and_unpinned_actions(tmp_path):
    wf = GOOD_WF.replace("  contents: read", "  contents: write").replace(f"@{SHA}", "@v4")
    rep = static_checks(_repo(tmp_path, wf))
    assert _status(rep, "token-permissions") == {"FAIL"}
    assert _status(rep, "action-pinning") == {"WARN"}
    assert "WARN" in _status(rep, "token-permissions") | _status(rep, "action-pinning")


def test_missing_permissions_warns(tmp_path):
    rep = static_checks(_repo(tmp_path, GOOD_WF.replace("permissions:\n  contents: read\n", "")))
    assert _status(rep, "token-permissions") == {"WARN"}


def test_secrets_in_gate_job_fail(tmp_path):
    wf = GOOD_WF.replace(
        '- run: aicrg check --base "$BASE" --head "$HEAD"',
        '- run: aicrg check --base "$BASE" --head "$HEAD"\n        env:\n          K: ${{ secrets.DEPLOY_KEY }}',
    )
    rep = static_checks(_repo(tmp_path, wf))
    assert _status(rep, "gate-secrets") == {"FAIL"}


def test_self_modifiable_policy_warns(tmp_path):
    rep = static_checks(_repo(tmp_path, policy="version: 1\n"))
    assert _status(rep, "policy-protected") == {"WARN"}
    assert _status(rep, "acceptance-config") == {"WARN"}


def test_invalid_policy_fails(tmp_path):
    rep = static_checks(_repo(tmp_path, policy="version: 1\nbogus: 1\n"))
    assert _status(rep, "policy") == {"FAIL"}


def test_unparseable_workflow_is_unknown_not_pass(tmp_path):
    root = _repo(tmp_path)
    (root / ".github" / "workflows" / "broken.yml").write_text("jobs: [unclosed\n")
    rep = static_checks(root)
    assert _status(rep, "workflow-parse") == {"UNKNOWN"}
    assert rep.verdict() == "UNKNOWN"


# ------------------------------------------------------------------------------ github


def _api(rules=None, protection=None, rules_status=200, prot_status=404):
    def get(path):
        if "/rules/branches/" in path:
            return rules_status, rules
        if path.endswith("/protection"):
            return prot_status, protection
        return 404, None

    return get


def test_github_permission_denied_is_unknown():
    rep = github_checks("o/r", "main", ["gate"], _api(rules_status=403, prot_status=403))
    assert rep.verdict() == "UNKNOWN"
    assert all(c.status == "UNKNOWN" for c in rep.checks)


def test_github_gate_not_required_fails():
    rules = [
        {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "lint"}]},
        }
    ]
    rep = github_checks("o/r", "main", ["gate"], _api(rules))
    assert _status(rep, "github-required-check") == {"FAIL"}


def test_github_fully_enforced():
    rules = [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [{"context": "gate"}],
                "strict_required_status_checks_policy": True,
            },
        },
        {
            "type": "workflows",
            "parameters": {"workflows": [{"path": ".github/workflows/gate.yml"}]},
        },
    ]
    rep = github_checks("o/r", "main", ["gate"], _api(rules))
    assert rep.verdict(strict=True) == "PASS", [c.to_json() for c in rep.checks]


def test_github_classic_protection_without_strict_warns():
    prot = {
        "required_status_checks": {"contexts": ["ci / gate"], "strict": False},
        "enforce_admins": {"enabled": True},
    }
    rep = github_checks("o/r", "main", ["gate"], _api([], prot, prot_status=200))
    assert _status(rep, "github-required-check") == {"PASS"}
    assert _status(rep, "github-up-to-date") == {"WARN"}
    assert _status(rep, "github-required-workflow") == {"WARN"}


def test_cli_exit_codes(tmp_path, capsys):
    root = _repo(tmp_path)
    assert main(["doctor", "--path", str(root)]) == 0
    assert main(["doctor", "--path", str(root), "--strict"]) in (0, 1)
    bad = _repo(tmp_path / "b", GOOD_WF.replace("aicrg check", "pytest"))
    assert main(["doctor", "--path", str(bad)]) == 1
    assert "DOCTOR: FAIL" in capsys.readouterr().out
