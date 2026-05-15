-- ------------------------------------------------------------------------
-- AWS trust-policy-rewrite privilege escalation: retrospective hunt
-- ------------------------------------------------------------------------
-- Finds iam:UpdateAssumeRolePolicy events followed within 10 minutes by
-- sts:AssumeRole on the same role by the same principal.
--
-- Designed for AWS Athena over a CloudTrail S3 archive, or for CloudTrail
-- Lake's SQL query interface. Adjust the table name to match your environment:
--   - Athena:        cloudtrail_logs (or your configured table name)
--   - CloudTrail Lake: the event data store ID
--
-- Tunables:
--   - Lookback window: 7 days (change in both CTEs)
--   - Correlation window: 10 minutes
--
-- Output columns let you triage quickly:
--   - seconds_between:   how tight the escalation was
--   - new_trust_policy:  inspect to see what changed (often MFA condition removed)
--   - caller_mfa_authenticated: was the bypass session itself MFA-backed?
--   - update_source_ip vs assume_source_ip: same actor or laundered?
-- ------------------------------------------------------------------------

WITH trust_updates AS (
  SELECT
    eventTime                                    AS update_time,
    userIdentity.arn                             AS principal_arn,
    requestParameters.roleName                   AS role_name,
    requestParameters.policyDocument             AS new_trust_policy,
    eventID                                      AS update_event_id,
    sourceIPAddress                              AS update_source_ip,
    userAgent                                    AS update_user_agent
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName   = 'UpdateAssumeRolePolicy'
    AND eventTime >= current_timestamp - INTERVAL '7' DAY
),
role_assumptions AS (
  SELECT
    eventTime                                    AS assume_time,
    userIdentity.arn                             AS principal_arn,
    regexp_extract(requestParameters.roleArn,
                   'role/(.+)$', 1)              AS role_name,
    eventID                                      AS assume_event_id,
    sourceIPAddress                              AS assume_source_ip,
    responseElements.assumedRoleUser.arn         AS assumed_role_arn,
    CAST(userIdentity.sessionContext.attributes.mfaAuthenticated AS BOOLEAN)
                                                 AS caller_mfa_authenticated
  FROM cloudtrail_logs
  WHERE eventSource = 'sts.amazonaws.com'
    AND eventName   = 'AssumeRole'
    AND eventTime >= current_timestamp - INTERVAL '7' DAY
)
SELECT
  t.update_time,
  a.assume_time,
  date_diff('second', t.update_time, a.assume_time)  AS seconds_between,
  t.principal_arn,
  t.role_name,
  t.update_event_id,
  a.assume_event_id,
  t.update_source_ip,
  a.assume_source_ip,
  a.caller_mfa_authenticated,
  t.update_user_agent,
  t.new_trust_policy
FROM trust_updates t
JOIN role_assumptions a
  ON  t.principal_arn = a.principal_arn
  AND t.role_name     = a.role_name
  AND a.assume_time BETWEEN t.update_time
                        AND t.update_time + INTERVAL '10' MINUTE
ORDER BY t.update_time DESC;

-- ------------------------------------------------------------------------
-- Tuning notes:
--
-- 1. Filter out IaC service identities. Add to the trust_updates WHERE clause:
--      AND userIdentity.arn NOT LIKE '%role/AWSReservedSSO_Terraform%'
--      AND userIdentity.arn NOT LIKE '%role/cdk-cfn-execution-role%'
--    Tune to match your pipeline identities.
--
-- 2. For high-value roles only: add to both CTEs:
--      AND role_name IN ('admin-break-glass', 'production-deploy', ...)
--
-- 3. If you have GuardDuty enabled, you may also see findings of type
--    'Persistence:IAMUser/AnomalousBehavior' for the same activity — correlate
--    on event IDs.
--
-- 4. To detect the WIDER pattern (any IAM mutation that weakens a role
--    followed by AssumeRole), expand the eventName filter in trust_updates to
--    include: PutRolePolicy, AttachRolePolicy, DeleteRolePermissionsBoundary.
-- ------------------------------------------------------------------------
