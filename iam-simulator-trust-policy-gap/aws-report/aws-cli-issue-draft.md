# GitHub Issue Draft

**Target repo:** [`aws/aws-cli`](https://github.com/aws/aws-cli/issues) — the underlying API behavior is in the IAM service, but `aws-cli` is the most user-facing surface. If closed as "service-side", refile via AWS Support or against the appropriate SDK repo.

---

## Title

`iam simulate-principal-policy` / `iam simulate-custom-policy` ignore `--resource-policy` for `sts:Assume*` actions — verdict diverges from live IAM engine and from IAM Access Analyzer

## Summary

The IAM policy simulator (`aws iam simulate-principal-policy` and `aws iam simulate-custom-policy`) parses and structurally validates role trust policies passed via `--resource-policy`, but silently discards them before evaluation for any action in the `sts:Assume*` family. The simulator's verdict for these actions is derived entirely from the identity policy.

This causes the simulator's output to diverge from both:

1. **The live IAM engine.** A trust policy that explicitly denies the caller is reported as `"allowed"` by the simulator and as `AccessDenied` by `sts:AssumeRole`.
2. **AWS IAM Access Analyzer.** The same trust-policy weakening (removing an MFA condition) is flagged as `"FAIL: grants new access"` by `accessanalyzer check-no-new-access` and as unchanged (`"allowed"` for both versions) by the simulator.

Verified across 11 test cases spanning four condition operators (`Bool`, `IpAddress`, `NumericLessThan`, `StringEquals`), three condition keys (`aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:MultiFactorAuthAge`), two STS action variants (`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`), and four trust-policy structural patterns (`Allow`, `Deny`, `NotPrincipal`, federated principal). Full matrix and raw output: https://github.com/RohanDS2024/iam-simulator-trust-policy-gap

## Expected behavior

When `--resource-policy` is provided and the action is `sts:Assume*`, the simulator should evaluate the trust policy against the request, including:

- Matching the `Principal` element
- Exercising `Condition` keys against `--context-entries` values
- Applying explicit `Deny` statements
- Honoring `NotPrincipal` exclusions

This is how the production IAM engine evaluates `sts:AssumeRole` per AWS's [April 2024 trust policy behavior clarification](https://aws.amazon.com/blogs/security/announcing-an-update-to-iam-role-trust-policy-behavior/), and it is also how AWS IAM Access Analyzer evaluates the same policies (verified in Test 11 of the linked reproducer suite).

## Actual behavior

For `sts:Assume*` actions, the `--resource-policy` parameter is silently discarded after parse-time validation. The simulator's verdict is derived entirely from the identity policy. Trust policies passed via `--resource-policy` never appear in `MatchedStatements`, regardless of whether they would allow, deny, or condition the action — except in the narrow case of `Service`-type Principals, which are rejected at parse time with `InvalidInput: Principal of type Service is not supported`. This indicates the parser is connected; the evaluator is not.

## Minimal reproducer

```bash
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:user/<user-with-AdministratorAccess>"
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

**Expected**: `"EvalDecision": "explicitDeny"` (explicit Deny always wins under IAM evaluation).
**Actual**: `"EvalDecision": "allowed"`, with only the identity policy (`AdministratorAccess`) in `MatchedStatements`. The Deny statement passed via `--resource-policy` is not acknowledged in the output at all.

A control test using `s3:GetObject` with an equivalent bucket policy confirms `--resource-policy` is wired up correctly for non-STS actions.

## Triangulation evidence

For semantically equivalent inputs, three AWS-native evaluators produce three different conclusions:

| AWS-native tool | Verdict on explicit-Deny trust policy |
|---|---|
| `simulate-principal-policy` | `"allowed"` |
| Live `sts:AssumeRole` API | `AccessDenied` |
| `accessanalyzer check-no-new-access` (vs permissive baseline) | `FAIL: grants new access` |

For the MFA-required → MFA-removed weakening (the trust-policy regression defenders most need to catch):

| AWS-native tool | Strong policy (MFA req'd) | Weak policy (MFA removed) | Distinguishable? |
|---|---|---|---|
| `simulate-principal-policy` (context MFA=false) | `"allowed"` | `"allowed"` | No |
| `accessanalyzer check-no-new-access` | (baseline) | `FAIL: grants new access in statement 0` | Yes |

The simulator gives **identical verdicts** for two trust policies AWS's Access Analyzer flags as materially different.

## Environment

```
aws-cli/2.34.47 Python/3.14.4 Linux/6.17.0-23-generic exe/aarch64.ubuntu.24
Ubuntu 24.04.4 LTS, kernel 6.17, aarch64
Region: us-east-1
Partition: aws (commercial)
Caller: IAM user, AdministratorAccess only attached policy
Permissions boundary: none
AWS Organizations: not a member (no SCPs possible)
Authentication: long-term IAM access keys
```

The environment is intentionally minimal: no permissions boundaries, no SCPs, no inline policies, no federation. Any divergence between the simulator and the live engine cannot be attributed to environmental factors.

## Security impact

Security teams use the IAM policy simulator for CI/CD validation of policy changes. For `sts:Assume*`, the simulator's output cannot be trusted to reflect production IAM behavior:

- **False positives** for the defender: simulator reports `"allowed"` when production denies. Common when a trust policy has an MFA condition or principal restriction. Leads to wasted investigation and risk that defenders weaken other controls to "compensate" for a phantom problem.
- **False negatives** for the defender: simulator reports `"implicitDeny"` / `"explicitDeny"` when production allows. Most dangerous case is verifying that a quarantine `Deny` on a compromised principal is in effect — the simulator returns the answer the defender wants, even when production behavior contradicts it.

A CI/CD pipeline that gates IAM changes on simulator output is currently unable to catch trust-policy regressions for `sts:Assume*`. Access Analyzer is the working alternative for this use case.

## Suggested fix

Either:

1. **Document the limitation.** Add a "Limitations" section to the [SimulatePrincipalPolicy API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html) and [SimulateCustomPolicy API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html) noting that `--resource-policy` is not honored for `sts:Assume*` actions, and pointing users to IAM Access Analyzer (`check-no-new-access`, `check-access-not-granted`) as the supported alternative for trust-policy validation.

2. **Fix the simulator.** Update the evaluation engine inside the simulator to apply AND-semantics for `sts:Assume*` against the trust policy, mirroring the behavior already implemented in Access Analyzer.

Option 1 is much cheaper and resolves user-facing confusion immediately. Option 2 is the genuine fix.

## Related: STS authentication preconditions unmodeled

A distinct but related issue surfaced during testing: the simulator returns `"allowed"` when an IAM user attempts `sts:AssumeRoleWithWebIdentity`, despite this action being structurally invocable only with an OIDC web identity token (never by an IAM user with long-term access keys). The simulator does not model action-level authentication preconditions. This may warrant a separate issue.

## References

- AWS re:Post: ["iam role trust policy behavior"](https://www.repost.aws/questions/QU4Kr2A6bpRtO8haGVu9hP6g/iam-role-trust-policy-behavior) — *"Role trust policies and KMS key policies are exceptions to this logic, because they must explicitly allow access for principals."*
- AWS Security Blog: ["Announcing an update to IAM role trust policy behavior"](https://aws.amazon.com/blogs/security/announcing-an-update-to-iam-role-trust-policy-behavior/) (April 2024)
- Full reproducer set with environment captures and raw output: https://github.com/RohanDS2024/iam-simulator-trust-policy-gap

## Reporter

Rohan Devikoppa Shreedhara — Florida Atlantic University (MS Computer Science, Cybersecurity).
GitHub: [@RohanDS2024](https://github.com/RohanDS2024) · LinkedIn: [rohan-devikoppa-shreedhara](https://www.linkedin.com/in/rohan-devikoppa-shreedhara-97a192216/)
