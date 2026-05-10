# Fixture F2 — synthetic: aws s3 cp on production secrets bucket

## Alert summary (vendor=auditd)
```
rule.id: 100777
rule.description: Sensitive command — aws s3 cp on production secrets bucket
rule.level: 12
rule.groups: [auditd, command-audit, sensitive-data-access]
data.cmdline: "/usr/local/bin/aws s3 cp s3://prod-secrets/keys.json /tmp/.cache.json"
data.uid: 1042
data.user: deploybot
data.pid: 28741
data.ppid: 28702
data.proc.name: aws
data.proc.pname: bash
data.tty: pts/3
agent.name: prod-jumphost-04
agent.ip: 10.20.30.41
predecoder.timestamp: 2026-05-05T03:14:08.412Z
mitre.technique: [Cloud Storage Object Discovery]
mitre.id: [T1530]
```

## CONTEXTUALIZE prologue (synthetic)
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|jumphost|prod-jumphost-04|
v-002|identity|service-account|deploybot|kind=service-account;uid=1042
v-003|object|cloud-secret|s3://prod-secrets/keys.json|
v-004|process|command-exec|aws|cmdline=aws s3 cp s3://prod-secrets/keys.json /tmp/.cache.json;ppid=28702;tty=pts/3

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|invoked|v-002|v-004|2026-05-05T03:14:08.412Z|runtime-audit:auditd|on=v-001
e-002|read_object|v-004|v-003|2026-05-05T03:14:08.412Z|runtime-audit:auditd|
```

## Pre-loop classification facts (from environment knowledge)
- `prod-jumphost-04` is classified `production-jumphost` per `environment/context/host-classes.md`
- `deploybot` is a service account legitimately used by both:
  - the CI/CD pipeline (cron-launched, no tty, parent process is the deploy job runner)
  - on-call SRE manual operations (interactive ssh session, has a tty, parent is bash)
- `prod-secrets/keys.json` is classified `production-credential-store` per `environment/context/data-classes.md` — access is permitted for the deploy pipeline and named on-call SREs, both audited
- The audit event carries `tty=pts/3`, `proc.pname=bash`, suggesting an interactive context — but that alone does not confirm SRE vs adversary

## Phase entry
You are PREDICT loop 1. CONTEXTUALIZE established the entities above. No GATHER has run yet. No playbook hypothesis seeds are available — reason from first principles. The genuinely-open question is whether the deploybot credential is being used by (a) an on-call SRE doing an authorized rotation, (b) the CI/CD deploy pipeline, or (c) someone who has obtained the deploybot credential and is exfiltrating. These three actors leave observably different audit trails (parent process, tty presence, shell history, change-management ticket linkage, IP reputation of the origin SSH session).
