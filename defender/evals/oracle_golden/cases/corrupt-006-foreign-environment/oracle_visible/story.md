0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts — long-lived IAM access keys used from an external host. |

1. Attack story

The attacker holds long-lived AWS IAM access keys for the service principal
`svc-billing-prod` in account `4471-0092-8815`, obtained from a leaked CI
environment file. From an external host the attacker uses the keys
programmatically via the AWS CLI [T1078.004], calling `sts:GetCallerIdentity`
to confirm them and then `s3:ListBuckets` and `s3:GetObject` against the bucket
`acme-invoices-archive` in `eu-west-1`. The attacker never logs into the AWS
console and never assumes a role. Roughly four hundred objects are read over
eleven minutes, after which the session ends.

2. Bypass

The cover is that `svc-billing-prod` reads this bucket on a schedule as part of
the month-end invoice export, so object reads under those keys are routine for
this principal. The attacker relies on staying inside the principal's ordinary
API surface and never touching IAM, console login, or any role assumption.
