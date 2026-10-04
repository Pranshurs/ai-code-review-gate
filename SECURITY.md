# Security policy

AI Code Review Gate is pre-release software. Its security claims and limits are
in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
"Report a vulnerability" (Security → Advisories) on this repository. Do not open a
public issue. Include the AICRG version or commit, a minimal reproduction (a
patch plus contract is ideal), and the expected vs actual decision.

Especially in scope:

* any input that makes the gate return **PASS** when a stage failed or a
  blocking condition holds (fail-open);
* any way for a patch to change the contract it is evaluated under;
* any way to make `aicrg verify-receipt` accept a stale or edited receipt;
* credential leakage into receipts, logs or reviewer-model requests;
* terminal or Markdown injection through rendered output.

Detection misses (a bad patch the heuristics do not catch) are welcome as normal
issues with a corpus case, unless they reveal one of the above.
