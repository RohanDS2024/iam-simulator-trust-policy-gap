#!/usr/bin/env bash
# capture-env.sh
# Captures the exact runtime environment for the test matrix in EXTENDED_TESTS.md.
# Output is appended to environment.txt for inclusion in the writeup.
#
# Usage:
#   bash experiments/capture-env.sh > environment.txt 2>&1

set +e  # don't bail on individual command failures — failure modes are themselves data

echo "================================================================"
echo "ENVIRONMENT CAPTURE — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"

echo ""
echo "--- CLI version ---"
aws --version

echo ""
echo "--- OS / kernel ---"
uname -a
if [ -f /etc/os-release ]; then
  head -5 /etc/os-release
fi

echo ""
echo "--- CLI configuration ---"
aws configure list
echo "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-<unset>}"
echo "AWS_REGION=${AWS_REGION:-<unset>}"
echo "Configured region: $(aws configure get region 2>/dev/null || echo '<not set>')"

echo ""
echo "--- Caller identity ---"
aws sts get-caller-identity
PARTITION=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null | cut -d: -f2)
echo "Partition: $PARTITION  (aws=commercial, aws-us-gov=GovCloud, aws-cn=China)"

echo ""
echo "--- Organization context ---"
aws organizations describe-organization 2>&1 | head -20
echo ""
echo "--- Service Control Policies attached to this account ---"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws organizations list-policies-for-target \
  --target-id "$ACCOUNT_ID" \
  --filter SERVICE_CONTROL_POLICY 2>&1 | head -20

echo ""
echo "--- Caller's identity policies ---"
CALLER_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
if echo "$CALLER_ARN" | grep -q ':user/'; then
  CALLER_USER=$(echo "$CALLER_ARN" | sed 's|.*:user/||')
  echo "Caller is IAM user: $CALLER_USER"
  echo ""
  echo "  Attached managed policies:"
  aws iam list-attached-user-policies --user-name "$CALLER_USER" 2>&1
  echo ""
  echo "  Inline policies:"
  aws iam list-user-policies --user-name "$CALLER_USER" 2>&1
  echo ""
  echo "  Permissions boundary:"
  aws iam get-user --user-name "$CALLER_USER" --query 'User.PermissionsBoundary' --output json 2>&1
  echo ""
  echo "  Group memberships:"
  aws iam list-groups-for-user --user-name "$CALLER_USER" --query 'Groups[].GroupName' --output text 2>&1
elif echo "$CALLER_ARN" | grep -q ':assumed-role/'; then
  CALLER_ROLE=$(echo "$CALLER_ARN" | sed 's|.*:assumed-role/||' | cut -d/ -f1)
  echo "Caller is assumed role: $CALLER_ROLE"
  echo ""
  echo "  Attached managed policies:"
  aws iam list-attached-role-policies --role-name "$CALLER_ROLE" 2>&1
  echo ""
  echo "  Inline policies:"
  aws iam list-role-policies --role-name "$CALLER_ROLE" 2>&1
fi

echo ""
echo "--- Target role's current trust policy (will be the baseline for test 10) ---"
if [ -n "${TARGET_ROLE:-}" ]; then
  aws iam get-role --role-name "$TARGET_ROLE" --query 'Role.AssumeRolePolicyDocument' --output json 2>&1
else
  echo "TARGET_ROLE env var not set — skipping. Set it and rerun to capture target trust policy."
fi

echo ""
echo "--- Authentication mechanism heuristic ---"
if [ -n "${AWS_SESSION_TOKEN:-}" ]; then
  echo "Session-token credentials detected (temporary; STS-derived)."
elif aws configure list 2>/dev/null | grep -q 'sso'; then
  echo "AWS SSO / IAM Identity Center likely in use."
else
  echo "Long-term access keys likely (no session token, no SSO indicators)."
fi

echo ""
echo "================================================================"
echo "END OF ENVIRONMENT CAPTURE"
echo "================================================================"
