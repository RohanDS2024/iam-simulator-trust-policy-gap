#!/usr/bin/env bash
# run-extended.sh
# Runs Tests 5-10 from EXTENDED_TESTS.md, the additional cases that close
# specific rebuttal vectors not covered by the original four.
#
# Tests 5-9 are non-destructive (no resource changes).
# Test 10 temporarily modifies the trust policy on $TARGET_ROLE — requires
# iam:UpdateAssumeRolePolicy and will restore the original on completion.
#
# Usage:
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
#   export PRINCIPAL_USER="iamws-lab-default"
#   export TARGET_ROLE="iamws-privileged-admin-role"
#   bash run-extended.sh

set -u

: "${ACCOUNT_ID:?must set ACCOUNT_ID}"
: "${PRINCIPAL_USER:?must set PRINCIPAL_USER}"
: "${TARGET_ROLE:?must set TARGET_ROLE}"

PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${PRINCIPAL_USER}"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${TARGET_ROLE}"
OWNER_ARN="arn:aws:iam::${ACCOUNT_ID}:root"

hr() { printf '\n=================================================================\n%s\n=================================================================\n' "$1"; }

# ----------------------------------------------------------------
# TEST 5 — IpAddress condition
# ----------------------------------------------------------------
hr "TEST 5 — IpAddress condition (closes 'maybe just Bool operator')"

IP_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.1/32"}}}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$IP_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --context-entries ContextKeyName=aws:SourceIp,ContextKeyValues=203.0.113.42,ContextKeyType=ip \
  --query 'EvaluationResults[0]'

# ----------------------------------------------------------------
# TEST 6 — NumericLessThan + aws:MultiFactorAuthAge
# ----------------------------------------------------------------
hr "TEST 6 — NumericLessThan + MultiFactorAuthAge (closes 'maybe just MFAPresent')"

AGE_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"300"}}}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$AGE_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --context-entries ContextKeyName=aws:MultiFactorAuthAge,ContextKeyValues=99999,ContextKeyType=numeric \
  --query 'EvaluationResults[0]'

# ----------------------------------------------------------------
# TEST 7 — sts:AssumeRoleWithWebIdentity
# ----------------------------------------------------------------
hr "TEST 7 — AssumeRoleWithWebIdentity (closes 'maybe federated paths work')"

OIDC_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::'${ACCOUNT_ID}':oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:Example/Repo:ref:refs/heads/main"}}}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRoleWithWebIdentity \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$OIDC_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --context-entries ContextKeyName=token.actions.githubusercontent.com:sub,ContextKeyValues=repo:Different/Repo:ref:refs/heads/main,ContextKeyType=string \
  --query 'EvaluationResults[0]'

# ----------------------------------------------------------------
# TEST 8 — NotPrincipal
# ----------------------------------------------------------------
hr "TEST 8 — NotPrincipal (closes 'maybe structural variants are evaluated')"

NOTPRINCIPAL_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$NOTPRINCIPAL_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --query 'EvaluationResults[0]'

# ----------------------------------------------------------------
# TEST 9 — Service principal in trust policy
# ----------------------------------------------------------------
hr "TEST 9 — Service principal (closes 'maybe service principals are handled')"

SERVICE_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$SERVICE_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --query 'EvaluationResults[0]'

# ----------------------------------------------------------------
# TEST 10 — Triangulation: simulator vs live API vs IAM Access Analyzer
# DESTRUCTIVE: temporarily modifies the trust policy on $TARGET_ROLE
# ----------------------------------------------------------------
hr "TEST 10 — Triangulation (DESTRUCTIVE — temporarily modifies trust policy)"

echo ""
echo "Snapshotting original trust policy of $TARGET_ROLE..."
ORIGINAL_TRUST=$(aws iam get-role \
  --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json)
echo "$ORIGINAL_TRUST" > /tmp/original-trust.json
echo "Snapshot saved to /tmp/original-trust.json"

echo ""
echo "Applying explicit-Deny trust policy..."
DENY_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'
aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document "$DENY_TRUST"

# Give IAM a few seconds to propagate (trust policy updates are usually instant
# but eventual consistency is documented; sleep avoids a race on the next call).
sleep 5

echo ""
echo "--- Verdict A: simulate-principal-policy ---"
aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$DENY_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --query 'EvaluationResults[0].EvalDecision'

echo ""
echo "--- Verdict B: live IAM engine (sts:AssumeRole) ---"
aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name triangulation-test 2>&1 | head -3

echo ""
echo "--- Verdict C: IAM Access Analyzer (check-no-new-access) ---"
PERMISSIVE_REFERENCE='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'
aws accessanalyzer check-no-new-access \
  --existing-policy-document "$PERMISSIVE_REFERENCE" \
  --new-policy-document "$DENY_TRUST" \
  --policy-type RESOURCE_POLICY 2>&1

# ----------------------------------------------------------------
# Restore original trust policy
# ----------------------------------------------------------------
echo ""
echo "Restoring original trust policy..."
aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document "$ORIGINAL_TRUST"

echo "Verifying restoration matches snapshot..."
aws iam get-role --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument' --output json > /tmp/restored-trust.json

if diff <(echo "$ORIGINAL_TRUST" | jq -S . 2>/dev/null) <(jq -S . /tmp/restored-trust.json 2>/dev/null) >/dev/null 2>&1; then
  echo "OK — trust policy restored to original state."
else
  echo "WARNING — restored policy differs from snapshot. Manual review needed:"
  echo "  Original: /tmp/original-trust.json"
  echo "  Restored: /tmp/restored-trust.json"
fi

hr "DONE — fill in 'Observed' column of EXTENDED_TESTS.md from these results"
