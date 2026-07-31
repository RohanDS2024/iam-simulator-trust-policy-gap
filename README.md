# AWS IAM Policy Simulator Silently Discards Role Trust Policies for `sts:Assume*` Actions

**TL;DR**: `aws iam simulate-principal-policy` and `aws iam simulate-custom-policy` parse and validate role trust policies passed via `--resource-policy`, then discard them before evaluation for any `sts:Assume*` action. Trust policies that explicitly *deny* the caller are reported as `"allowed"`. Condition keys (`aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:MultiFactorAuthAge`, etc.) are never exercised. Structural variants (`NotPrincipal`, federated principals) are ignored. The simulator's verdict diverges from both the live IAM engine *and* AWS IAM Access Analyzer when evaluating the same trust policy.

This affects defenders who use the simulator to validate trust-policy controls — principal restrictions, MFA conditions, source-IP conditions, explicit denies used for quarantine. The simulator can return `"allowed"` for `sts:AssumeRole` requests that production IAM denies.

Verified across **11 test cases** spanning four condition operators, three condition keys, two STS action variants, four trust-policy structural patterns, and three independent AWS-native evaluation surfaces. See [`EXTENDED_TESTS.md`](./EXTENDED_TESTS.md) for the full matrix and raw output.

**Discovered:** May 2026
## Disclosure status

- **GitHub issue**: [aws/aws-cli#10314](https://github.com/aws/aws-cli/issues/10314) — filed 2026-05-15. **Open**, triaged by AWS as `bug` (labels: `bug`, `iam`, `p3`, `service-api`) and assigned to an AWS maintainer.
- **AWS Support ticket**: **closed** — AWS classified the behaviour as **known**.
- **Position taken here**: AWS is right that the *non-support* is documented (see [What AWS documents](#what-aws-documents-and-why-this-is-still-a-finding) below). The finding is not "undocumented behaviour" — it is that the documented non-support **fails open** rather than erroring, and that no signal distinguishes an unevaluated trust policy from an evaluated one.

Updates will be posted here as the disclosure progresses. _Last updated: 2026-07-30._
**Author:** Rohan Devikoppa Shreedhara — [GitHub](https://github.com/RohanDS2024) · [LinkedIn](https://www.linkedin.com/in/rohan-devikoppa-shreedhara-97a192216/)

---

## Background

### Two evaluation models inside IAM

AWS IAM uses two distinct authorization models depending on the action:

1. **OR semantics** (most actions on resources with resource-based policies). Access is granted if **either** the identity policy or the resource policy allows it. Used by S3 bucket policies, SNS, SQS, Secrets Manager, Lambda function policies, etc.

2. **AND semantics** (role trust policies for `sts:AssumeRole`, and KMS key policies). Access requires **both** the identity policy and the resource policy to allow it. Trust policies must explicitly name the principal — there is no implicit trust based on identity policy alone.

AWS re:Post documents this exception explicitly: *"Role trust policies and KMS key policies are exceptions to this logic, because they must explicitly allow access for principals."* AWS reaffirmed the AND-semantics rule for `sts:AssumeRole` in their [April 2024 IAM role trust policy behavior announcement](https://aws.amazon.com/blogs/security/announcing-an-update-to-iam-role-trust-policy-behavior/).

### What the simulator is meant to do

`simulate-principal-policy` and `simulate-custom-policy` accept a `--resource-policy` parameter explicitly designed to let callers provide the resource-side policy for evaluation. For S3, KMS data operations, etc., this works correctly. The question this finding answers:

> Does `--resource-policy` correctly model role trust policies for `sts:Assume*` actions?

Answer: no — and the divergence is testable against AWS's own Access Analyzer, which gets it right on the same input.

### What AWS documents, and why this is still a finding

The IAM API reference for [`SimulatePrincipalPolicy`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html) states, under **both** the `ResourceArns` and `ResourcePolicy` parameters:

> "Simulation of resource-based policies isn't supported for IAM roles."

A role trust policy is a resource-based policy on a role, so this sentence covers the case in this repository. **This finding is therefore not a claim of undocumented behaviour, and AWS Support was correct to classify the underlying limitation as known.** That should be stated plainly by anyone citing this work.

What the documentation does *not* say is what happens when you try it anyway. Three things are worth separating:

1. **It fails open, not closed.** "Isn't supported" would ordinarily imply an error, a warning, or an omitted result. Instead the API returns a confident `"allowed"` — including for a trust policy whose only statement is an explicit `Deny` naming the caller.
2. **There is no signal to key on.** The discarded policy produces no `MissingContextValues`, no entry in `MatchedStatements`, and no field in the response distinguishing "trust policy evaluated and allowed" from "trust policy silently dropped". A caller cannot detect programmatically that its input was ignored — which is what makes this dangerous in automation rather than merely surprising at a terminal.
3. **The parameter is still accepted and parsed.** `--resource-policy` validates the document and rejects malformed input (e.g. `Service`-type Principals are rejected at parse time), which reasonably signals to a caller that the policy is being used. It is not.

The practical consequence stands regardless of documentation: a CI/CD guardrail built on `simulate-principal-policy` returns green for trust-policy regressions, and nothing in the response indicates the check was vacuous. The [workarounds](#workarounds) section lists what to use instead.

---

## The triangulation (headline evidence)

For the same trust policy that explicitly denies the caller, three AWS-native evaluation paths produce three different conclusions:

| AWS-native tool | Verdict on explicit-Deny trust policy | Correct? |
|---|---|---|
| `aws iam simulate-principal-policy` | `"allowed"` | ❌ |
| Live `sts:AssumeRole` API | `AccessDenied` | ✓ |
| `aws accessanalyzer check-no-new-access` (vs permissive baseline) | `FAIL: grants new access` | ✓ |

For the MFA-required vs MFA-removed comparison (which is the trust-policy weakening that defenders most need to catch):

| AWS-native tool | Verdict on "removing the MFA condition" |
|---|---|
| `simulate-principal-policy` (MFA-required, context MFA=false) | `"allowed"` |
| `simulate-principal-policy` (MFA-removed, context MFA=false) | `"allowed"` |
| `accessanalyzer check-no-new-access` | `FAIL: "The modified permissions grant new access compared to your existing policy."` |

The simulator gives **identical verdicts** for two trust policies AWS's Access Analyzer identifies as materially different. AWS demonstrably has the capability to evaluate trust policies correctly; the policy simulator does not exercise that capability for the `sts:Assume*` action family.

---

## Characterization (refined)

> The IAM policy simulator (`simulate-principal-policy` and `simulate-custom-policy`) parses and structurally validates the trust policy provided via `--resource-policy`, but discards it before evaluation for any action in the `sts:Assume*` family. Parse errors are surfaced (e.g., `Service`-type Principals are rejected at parse time); evaluation is not performed. As a result, `Effect`, `Condition`, `Principal`, and `NotPrincipal` elements of the trust policy have no influence on the simulator's verdict, regardless of operator, condition key, or context entries provided.

The simulator's verdict for `sts:Assume*` actions is derived **entirely from the identity policy** (`--policy-source-arn` or `--policy-input-list`). For a principal with `AdministratorAccess`, every trust policy yields `"allowed"` — including pure-Deny policies and policies that name a different principal entirely.

---

## Headline reproducer

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:user/<some-user-with-AdministratorAccess>"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/<any-role-you-own>"

# Trust policy that EXPLICITLY DENIES the caller
DENY_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$DENY_TRUST" \
  --resource-owner "arn:aws:iam::${ACCOUNT_ID}:root" \
  --query 'EvaluationResults[0]'
```

Expected (correct): `"explicitDeny"`, with the Deny statement in `MatchedStatements`.
Observed: `"allowed"`, with only the identity policy in `MatchedStatements`. The Deny statement passed via `--resource-policy` is not acknowledged anywhere in the output.

Full reproducer suite of 11 tests is in [`EXTENDED_TESTS.md`](./EXTENDED_TESTS.md) and runnable via [`experiments/run-all.sh`](./experiments/run-all.sh) + [`experiments/run-extended.sh`](./experiments/run-extended.sh).

---

## Why this matters

The defensive use cases for the IAM policy simulator are questions like:

- *"Will user X be blocked from assuming role Y if I add this MFA condition?"*
- *"Does this trust policy correctly restrict access to my admin role?"*
- *"If I deny a compromised principal in the role's trust policy, will the simulator confirm the block?"*

For `sts:Assume*`, the simulator returns wrong answers in both directions:

- **False positive for the defender** (simulator says `"allowed"`, production denies): the defender concludes a control is broken when it's fine. May lead to over-engineering compensating controls.
- **False negative for the defender** (simulator says implicit/explicit deny, production allows): the defender concludes a control is working when it isn't. May lead to misplaced confidence in MFA conditions, principal restrictions, or quarantine denies. **This is the dangerous direction.**

CI/CD pipelines that gate IAM changes on simulator output may pass through trust-policy regressions undetected. The Access Analyzer comparison above shows AWS already ships the right tool for this purpose — the simulator just isn't it.

---

## Workarounds

Do not rely on `simulate-principal-policy` or `simulate-custom-policy` for trust-policy verification on `sts:Assume*` actions. Use one of:

1. **AWS IAM Access Analyzer custom policy checks.** `access-analyzer check-no-new-access` and `check-access-not-granted` use a different evaluation engine that correctly handles trust-policy semantics. Confirmed working in Test 11.
2. **Live API call.** `aws sts assume-role` against the role and observe the response. Genuinely accurate; produces a CloudTrail event.
3. **Open-source simulators with explicit STS handling.** [`cloud-copilot/iam-simulate`](https://github.com/cloud-copilot/iam-simulate) ships an `StsServiceAuthorizer` class that explicitly models the AND-semantics case.
4. **Static linting.** Tools like `parliament`, `cloudsplaining`, and `cfn-guard` flag known-bad trust-policy patterns without simulating evaluation.

For identity policies, permissions boundaries, and non-trust resource policies (S3, KMS data ops, SNS, SQS, etc.), `simulate-principal-policy` remains reliable.

---

## Bonus finding: STS authentication preconditions unmodeled (Test 7)

The simulator returns `"allowed"` when an IAM user attempts `sts:AssumeRoleWithWebIdentity`. In production, this is structurally impossible: the action authenticates via OIDC web identity token, not via IAM credentials, so an IAM user cannot invoke it regardless of trust policy. The simulator does not model action-level authentication preconditions and will report `"allowed"` for actions the principal is structurally incapable of performing in production.

This is a distinct bug from the trust-policy discard but documented here because it surfaces in the same test surface.

---

## Detection: catching the bypass in the wild

The exploitation pattern enabled by trust-policy verification gaps is the **trust-policy-rewrite privilege escalation**: a principal with `iam:UpdateAssumeRolePolicy` modifies a privileged role's trust policy (removing MFA conditions, principal restrictions, or source-IP locks; or adding themselves as a trusted principal), then assumes the role. Maps to MITRE ATT&CK `T1098.001` (Account Manipulation: Additional Cloud Credentials) and `T1548.005` (Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access).

Detection artifacts in this repository:

- [`detection/sigma-rule.yml`](detection/sigma-rule.yml) — Sigma correlation rule for SIEM ingestion of CloudTrail events.
- [`detection/athena-query.sql`](detection/athena-query.sql) — Retrospective hunt query for CloudTrail Lake / Athena.
- [`detection/wazuh-rule.xml`](detection/wazuh-rule.xml) — Wazuh ruleset for the same correlation.

Key signal: `iam:UpdateAssumeRolePolicy` on a role followed within ~10 minutes by `sts:AssumeRole` on the same role by the same principal. High-fidelity in well-managed accounts where trust-policy edits are rare.

---

## Repository contents

```
.
├── README.md                       # this file
├── EXTENDED_TESTS.md               # full 11-test matrix with raw output and environment
├── experiments/
│   ├── capture-env.sh              # environment-spec capture
│   ├── run-all.sh                  # Tests 1-4 (original)
│   └── run-extended.sh             # Tests 5-10 (extended)
├── aws-report/
│   └── aws-cli-issue-draft.md      # ready-to-file GitHub issue text
└── detection/
    ├── sigma-rule.yml
    ├── athena-query.sql
    └── wazuh-rule.xml
```

---

## Acknowledgements

Discovered while working through the AWS IAM workshop (Permissions Boundaries & Condition Keys lab). Investigation methodology, test matrix design, and Access Analyzer triangulation refined in collaboration with Anthropic's Claude (Opus 4.7).
