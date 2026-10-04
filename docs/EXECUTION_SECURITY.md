# Execution security

Every evidence command — required checks, differential base runs, trusted
evidence, test-potency mutants — executes code chosen by someone else: the
candidate patch (head) or, for differential runs, the base. AICRG treats that
code as hostile. This document states what each executor does and does not
protect, and how to deploy it.

## Executors

| | `local` | `container` |
|---|---|---|
| Claim | **trusted-code mode, no sandbox** | isolation (not a proof) |
| User | the gate's own user | numeric unprivileged uid (default `65534:65534`; root is refused by the contract parser) |
| Filesystem | gate's filesystem; throwaway `git worktree` of the exact commit | only a throwaway export of the exact commit is mounted (`/workspace`); read-only root filesystem; size-limited `/tmp` tmpfs |
| Repository link | worktree's `.git` points back to the host repository | none: plain export, no `.git` (code cannot rewrite the gate's refs, hooks or `core.fsmonitor`) |
| Environment | inherited minus credential-looking variables (`TOKEN`, `SECRET`, `KEY`, `AWS_*`, `ACTIONS_ID_TOKEN*`, …) | **not inherited**: `HOME=/tmp`, a few fixed variables, and only the names listed in `execution.env_passthrough` |
| Network | host network | `--network none` unless the contract sets `network: enabled` |
| Privileges | gate's | `--cap-drop ALL`, `no-new-privileges`, no `--privileged`, no extra mounts, never the runtime socket |
| Limits | wall-clock timeout, process-group kill | wall-clock timeout (`docker kill`), `--cpus`, `--memory` (= swap), `--pids-limit` |
| Image | n/a | from the base contract; pin by digest (`image@sha256:…`); the receipt records the resolved image ID |

The runtime argv is built entirely inside AICRG
(`src/aicrg/evidence/executor.py`). The contract chooses values for a fixed
set of options; there is no "extra flags" escape hatch, so a contract cannot
add `--privileged`, host mounts, `--pid host`, or the Docker socket.

## Selection rules (fail closed)

* The **base contract's** `execution.executor` is a floor. An operator may
  upgrade `local` → `container` (`--executor container`), never downgrade:
  `--executor local` against a `container` contract is ERROR.
* If the container runtime or image is unavailable, the gate reports ERROR.
  It never falls back to local execution.
* Exit status 125 from the runtime (its own failure) is ERROR, not the check's
  FAIL.

## Workspace hygiene

* Evidence never runs in the developer's working tree: uncommitted or
  untracked files are not evidence.
* Trusted overlays and mutant writes use `safe_write`, which refuses `..`,
  absolute paths, `.git/`, and **never follows a symlink** planted by the
  patch (a `trusted_tests -> /home/runner` symlink is replaced by a real
  directory; nothing outside the workspace is touched).
* A report file already present at a check's `report.path` was committed by
  the patch; it is deleted before the tool runs and the receipt says so.
  After the run the report must be a regular file inside the workspace
  (symlinks and paths escaping through symlinked parents are ERROR).

## Adversarial tests

`tests/test_execution_boundary.py` runs a hostile probe inside a real
container and asserts what it observed: uid 65534, outbound network blocked,
a host secret environment variable absent, the host repository path absent,
no Docker socket, root filesystem read-only. It also checks timeout kill
(no container left behind), the missing-runtime path (ERROR, nothing run
locally), the downgrade refusal, contract rejection of root/host-network/
privileged/volume options, and that the container workspace has no `.git`.
CI runs these with `AICRG_REQUIRE_DOCKER=1`, so a missing runtime fails the
job instead of silently skipping.

## What containers do not give you

* **Kernel / runtime escapes.** A container shares the host kernel. Use
  ephemeral VMs (GitHub-hosted runners are single-use VMs) for real
  separation; consider gVisor/Kata via the runtime if you need more.
* **Covert behaviour of the code under test.** Candidate code can detect it is
  being evaluated and behave differently. Trusted evidence and potency make
  this harder to exploit, not impossible.
* **Network opt-in.** `network: enabled` lets candidate code exfiltrate
  anything it can read inside the container (which excludes host secrets,
  but includes the source tree).
* **Local mode.** With the local executor, candidate code can do anything
  the gate's user can, including leaving a background process that edits the
  receipt after the gate writes it. Use local mode only on ephemeral runners
  that hold no secrets, and never sign receipts in the same job.

## GitHub Actions

See [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md). In short: `pull_request` (never
`pull_request_target`), `permissions: contents: read`, `persist-credentials:
false`, no secrets in the gate job, SHA-pinned actions, and attest the
receipt in a **separate job** that never executes candidate code (an
`id-token: write` token in the gate job would let candidate code sign
anything as your workflow). `aicrg doctor` checks these properties.
