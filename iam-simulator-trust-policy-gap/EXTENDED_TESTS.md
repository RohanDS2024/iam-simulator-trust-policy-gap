# Extended Verification — Test Matrix and Results

Companion to [`README.md`](./README.md). Documents the full 10-test matrix
used to characterize the gap, including the environment under which testing
was performed and the observed results for each test.

## Environment

Captured via [`capture-env.sh`](./capture-env.sh) on 2026-05-15T18:25:20Z.

| Spec | Value |
|---|---|
| `aws-cli` | 2.34.47 (Python 3.14.4) |
| OS | Ubuntu 24.04.4 LTS (Noble Numbat) |
| Kernel | Linux 6.17.0-23-generic |
| Architecture | aarch64 (Apple Silicon via UTM emulation) |
| Region | us-east-1 |
| Partition | `aws` (commercial) |
| Account | 233053488138 |
| Caller | IAM user `iamws-lab-default` |
| Caller's identity policies | `AdministratorAccess` (AWS-managed) — only attached policy |
| Caller's inline policies | none |
| Caller's permissions boundary | **none** |
| Caller's group memberships | **none** |
| AWS Organizations | **not a member** (account is standalone — no SCPs possible) |
| Authentication mechanism | Long-term IAM access keys (no STS session, no SSO) |
| Target role | `iamws-privileged-admin-role` |
| Target role's baseline trust policy | `Allow` to `iamws-lab-default`, `Condition: Bool aws:MultiFactorAuthPresent = true` |

**Why this environment matters:** There are no permissions boundaries, no
SCPs, no inline policies, no federation, and no group policies in play. Any
divergence between the simulator's verdict and the live IAM engine's verdict
must originate in the simulator's evaluation logic — there is nothing else in
the environment that could mask, override, or compensate for a trust-policy
condition.

## Test design

Each test isolates a single variable and pairs the simulator's verdict with
the live IAM engine's verdict (or, for Tests 10–11, with IAM Access Analyzer
as a second AWS-native evaluator) so that every row is an end-to-end
comparison rather than a single data point.

## Results

| # | Axis | Identity policy | Trust policy | Action | Context | Expected (correct) | Observed (simulator) | Match? |
|---|---|---|---|---|---|---|---|---|
| 1 | Identity silent | Silent on STS | `Allow` unconditional | `sts:AssumeRole` | — | trust policy in `MatchedStatements`, `allowed` | trust policy absent; `implicitDeny` | ✓ confirms gap |
| 2 | **Control** (S3) | Allow `s3:GetObject` | `Allow` on bucket | `s3:GetObject` | — | `allowed`, both policies matched | `allowed`, both policies matched | ✓ baseline works |
| 3 | Explicit Deny in trust | `AdministratorAccess` | **`Deny` explicit** | `sts:AssumeRole` | — | `explicitDeny` | `allowed` | ✓ confirms gap |
| 4a | `Bool` MFA condition | `AdministratorAccess` | `Allow` if MFA=true | `sts:AssumeRole` | MFA=false | `implicitDeny` | `allowed` | ✓ confirms gap |
| 4b | `Bool` MFA condition | `AdministratorAccess` | `Allow` if MFA=true | `sts:AssumeRole` | MFA=true | `allowed` | `allowed` (correct by accident) | ✓ |
| 5 | `IpAddress` condition | `AdministratorAccess` | `Allow` if SourceIp=10.0.0.1/32 | `sts:AssumeRole` | SourceIp=203.0.113.42 | `implicitDeny` | `allowed` | ✓ confirms gap |
| 6 | `NumericLessThan` + `aws:MultiFactorAuthAge` | `AdministratorAccess` | `Allow` if MFAAge<300 | `sts:AssumeRole` | MFAAge=99999 | `implicitDeny` | `allowed` | ✓ confirms gap |
| 7 | Different STS action | `AdministratorAccess` | `Allow` if matching OIDC sub | `sts:AssumeRoleWithWebIdentity` | sub mismatch | `implicitDeny` | `allowed` + impossible action allowed for IAM user | ✓ confirms gap + bonus |
| 8 | `NotPrincipal` | `AdministratorAccess` | `Allow` for `NotPrincipal: <caller>` | `sts:AssumeRole` | — | `implicitDeny` (caller is excluded) | `allowed` | ✓ confirms gap |
| 9 | Service principal | `AdministratorAccess` | `Allow` only for `Service: ec2.amazonaws.com` | `sts:AssumeRole` | — | _wanted: `allowed` (gap); refines characterization_ | `InvalidInput: Principal of type Service is not supported` | ⚠ parser rejects — informative |
| 10a | **Triangulation A** (simulator) | `AdministratorAccess` | **`Deny` explicit** | `sts:AssumeRole` | — | `explicitDeny` | `allowed` | ✓ gap reproduced |
| 10b | **Triangulation B** (live API) | `AdministratorAccess` | **`Deny` explicit** | `sts:AssumeRole` | — | `AccessDenied` | `AccessDenied` | ✓ production correct |
| 11 | **Access Analyzer comparison** | n/a | MFA-required vs MFA-removed | `sts:AssumeRole` (conceptual) | — | `FAIL: new access` | `FAIL: "The modified permissions grant new access compared to your existing policy." reasons: [{statementIndex: 0}]` | ✓ Access Analyzer correct |
| 11b | Simulator on EXISTING_MFA | `AdministratorAccess` | `Allow` if MFA=true | `sts:AssumeRole` | MFA=false | `implicitDeny` | `allowed` | ✓ gap reproduced |
| 11c | Simulator on NEW_BYPASS | `AdministratorAccess` | `Allow` unconditional | `sts:AssumeRole` | MFA=false | `allowed` | `allowed` | — (correct in isolation; the simulator gave the *same* verdict as 11b for materially different policies) |

### Raw triangulation output (Tests 10–11)

**Test 10 — simulator vs live IAM engine, same explicit-Deny trust policy:**

```
--- Verdict A: simulate-principal-policy ---
"allowed"

--- Verdict B: live IAM engine (sts:AssumeRole) ---
An error occurred (AccessDenied) when calling the AssumeRole operation: User:
arn:aws:iam::233053488138:user/iamws-lab-default is not authorized to perform:
sts:AssumeRole on resource: arn:aws:iam::233053488138:role/iamws-privileged-admin-role
```

**Test 11 — IAM Access Analyzer comparing MFA-required vs MFA-removed trust policies:**

```
=== Access Analyzer: does NEW grant more access than EXISTING? ===
{
    "result": "FAIL",
    "message": "The modified permissions grant new access compared to your existing policy.",
    "reasons": [
        {
            "description": "New access in the statement with index: 0.",
            "statementIndex": 0
        }
    ]
}

=== Simulator verdict on EXISTING_MFA (with MFA=false context) ===
"allowed"

=== Simulator verdict on NEW_BYPASS (with MFA=false context) ===
"allowed"
```

The simulator gives **identical verdicts** for two trust policies that AWS's
own Access Analyzer identifies as materially different in terms of access
granted.

## Synthesis

Across 11 test cases spanning condition operators (`Bool`, `IpAddress`,
`NumericLessThan`), condition keys (`aws:MultiFactorAuthPresent`,
`aws:SourceIp`, `aws:MultiFactorAuthAge`), STS action variants
(`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`), trust-policy structures
(`Allow`, `Deny`, `NotPrincipal`), and three independent AWS-native
evaluation surfaces (simulator, live IAM engine, Access Analyzer), the
finding holds:

> **The IAM policy simulator (`simulate-principal-policy` and
> `simulate-custom-policy`) parses and structurally validates the trust
> policy provided via `--resource-policy`, but discards it before evaluation
> for any action in the `sts:Assume*` family. Parse errors are surfaced
> (e.g., `Service`-type Principals are rejected); evaluation is not
> performed. As a result, `Effect`, `Condition`, `Principal`, and
> `NotPrincipal` elements of the trust policy have no influence on the
> simulator's verdict, regardless of operator, condition key, or context
> entries provided.**

The simulator's verdict for `sts:Assume*` actions is therefore derived
**entirely from the identity policy** (`--policy-source-arn` or
`--policy-input-list`). For a principal with `AdministratorAccess` (which
allows `sts:AssumeRole` on `*`), every trust policy yields `"allowed"`,
including pure-Deny policies.

### Triangulation evidence (Tests 10–11)

For semantically equivalent inputs, three AWS-native evaluators produced
three different conclusions:

- `simulate-principal-policy`: `"allowed"` for a trust policy that explicitly denies the caller, and `"allowed"` for both the MFA-required and MFA-removed versions of an otherwise identical trust policy.
- Live `sts:AssumeRole` API: `AccessDenied` for the explicit-Deny trust policy.
- `accessanalyzer check-no-new-access`: `FAIL: "The modified permissions grant new access compared to your existing policy."` for the MFA-required → MFA-removed comparison, with the offending statement index identified.

Access Analyzer correctly identifies the same trust-policy weakening that
the simulator is blind to. AWS demonstrably has the capability to evaluate
trust policies correctly; the policy simulator does not exercise that
capability for the `sts:Assume*` action family.

### Bonus finding (Test 7)

`sts:AssumeRoleWithWebIdentity` cannot be invoked by an IAM user with
long-term access keys — the action authenticates via OIDC web identity
token, not IAM credentials. The simulator returned `"allowed"` for an IAM
user attempting this action. This is a distinct bug from the trust-policy
discard: the simulator does not model the authentication preconditions of
STS API actions and will report `"allowed"` for actions the principal is
structurally incapable of performing in production.

### Edge case (Test 9)

`Principal: { Service: "ec2.amazonaws.com" }` was rejected at parse time
with `InvalidInput: Principal of type Service is not supported`. This
refines the characterization above: the simulator's `--resource-policy`
parser does validate Principal types and reject some, but for the
structures it accepts (User, Federated, NotPrincipal, etc.), it discards
the policy before evaluation. Parse pathway is connected; evaluation
pathway is not.

## Reproducibility

All tests are runnable via [`run-extended.sh`](./run-extended.sh) (Tests
5–10 inclusive) and the inline block in the README for Tests 1–4. Test 11
is the Access Analyzer triangulation block executed manually after the
discovery that `check-no-new-access` is the appropriate API for the
MFA-weakening comparison. Total runtime: under 30 seconds against a
quiescent account.

Test 10 modifies the trust policy on `$TARGET_ROLE` temporarily and
restores it via snapshot+diff. Verified in this run: `OK — trust policy
restored to original state.`
