#!/usr/bin/env bash
# run-all.sh
# Reproduces all four experiments demonstrating that simulate-principal-policy /
# simulate-custom-policy ignore role trust policies for sts:AssumeRole.
#
# Prerequisites:
#   - aws CLI v2 configured
#   - Principal has iam:SimulatePrincipalPolicy, iam:SimulateCustomPolicy
#   - A target role ARN you own (the actual trust policy on the role is irrelevant —
#     each experiment overrides it via --resource-policy)
#
# Usage:
#   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
#   export PRINCIPAL_USER="iamws-lab-default"          # any user that has AdminAccess
#   export TARGET_ROLE="iamws-privileged-admin-role"   # any role you own
#   bash run-all.sh

set -u

: "${ACCOUNT_ID:?must set ACCOUNT_ID}"
: "${PRINCIPAL_USER:?must set PRINCIPAL_USER}"
: "${TARGET_ROLE:?must set TARGET_ROLE}"

PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${PRINCIPAL_USER}"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${TARGET_ROLE}"
OWNER_ARN="arn:aws:iam::${ACCOUNT_ID}:root"

SILENT_IDENTITY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'

echo "================================================================"
echo "EXPERIMENT 1: Silent identity + permissive trust policy"
echo "Expected (if simulator evaluates trust policy): 'allowed' with trust policy in MatchedStatements"
echo "Actual: ?"
echo "================================================================"

ALLOW_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'

aws iam simulate-custom-policy \
  --policy-input-list "$SILENT_IDENTITY" \
  --resource-policy "$ALLOW_TRUST" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-owner "$OWNER_ARN" \
  --caller-arn "$PRINCIPAL_ARN" \
  --query 'EvaluationResults[0]'

echo ""
echo "================================================================"
echo "EXPERIMENT 2 (CONTROL): same setup but for s3:GetObject"
echo "Expected: 'allowed' with bucket policy in MatchedStatements as 'Resource Policy'"
echo "Actual: ?"
echo "================================================================"

BUCKET_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::any-bucket/*"}]}'

aws iam simulate-custom-policy \
  --policy-input-list "$SILENT_IDENTITY" \
  --resource-policy "$BUCKET_POLICY" \
  --action-names s3:GetObject \
  --resource-arns "arn:aws:s3:::any-bucket/test.txt" \
  --resource-owner "$OWNER_ARN" \
  --caller-arn "$PRINCIPAL_ARN" \
  --query 'EvaluationResults[0]'

echo ""
echo "================================================================"
echo "EXPERIMENT 3: Explicit Deny in trust policy"
echo "Expected: 'explicitDeny' (Deny always wins in real IAM evaluation)"
echo "Actual: ?"
echo "================================================================"

DENY_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole"}]}'

aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$DENY_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --query 'EvaluationResults[0]'

echo ""
echo "================================================================"
echo "EXPERIMENT 4: Trust-policy MFA condition"
echo "Expected: 'implicitDeny' when MFA=false, 'allowed' when MFA=true"
echo "Actual: ?"
echo "================================================================"

MFA_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'${PRINCIPAL_ARN}'"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}'

echo "--- MFA context = false ---"
aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$MFA_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --context-entries ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=false,ContextKeyType=boolean \
  --query 'EvaluationResults[0].EvalDecision'

echo "--- MFA context = true ---"
aws iam simulate-principal-policy \
  --policy-source-arn "$PRINCIPAL_ARN" \
  --action-names sts:AssumeRole \
  --resource-arns "$ROLE_ARN" \
  --resource-policy "$MFA_TRUST" \
  --resource-owner "$OWNER_ARN" \
  --context-entries ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=true,ContextKeyType=boolean \
  --query 'EvaluationResults[0].EvalDecision'

echo ""
echo "================================================================"
echo "Done. Compare results against the table in README.md."
echo "================================================================"
