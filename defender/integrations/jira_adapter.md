# Jira

## Credential

For Jira Cloud use the `basic` scheme: the account's email address as `username` and an API token as `password`. The account needs permission to add comments to the issues the alerts name (and to read them back).

## Pitfalls

- The alert must carry the issue key (`ABC-123`), not the numeric issue id.
- `JIRA_SERVICE_DESK` picks the API, not the product edition: `yes` comments through Jira Service Management's request API (an internal comment), `no` through the plain REST issue API. Confirm which the maintainer's tickets live in before writing it.
