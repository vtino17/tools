# Security Model

## Trust boundary

`devhibernate.json` is executable repository configuration. Setup and service commands can run arbitrary shell code with the current user's permissions. Only use DevHibernate after reviewing configuration in repositories you trust.

## Secret handling

DevHibernate does not provide a secret vault.

- parent environment is deny-by-default
- `passEnv` explicitly names variables to copy at runtime
- state stores no environment map
- handoff stores no environment map
- CLI does not print copied values

Static `service.env` is not secret-safe because it lives in tracked JSON.

## Local proxy

- binds to `127.0.0.1`
- uses `.localhost` hostnames
- does not provide TLS or authentication
- should not be exposed through port forwarding without understanding the target service

## Process control

On Unix, DevHibernate terminates the process group started for each service. A service that deliberately daemonizes into another session may escape management. Such services should offer a foreground mode.

## Deletion safety

Normal deletion checks Git status and refuses a dirty worktree. `--force` explicitly permits discarding uncommitted changes in the worktree. Branch deletion is separately controlled by `--delete-branch`, `--keep-branch`, and configuration. `--force` never implies branch deletion.

## State integrity

State writes use temporary-file replacement. The MVP does not yet have a cross-process lock, so concurrent CLI mutations may race. Avoid running lifecycle writes concurrently in the same repository.

## Reporting vulnerabilities

Do not open public issues containing real secrets or sensitive repository paths. Report security concerns privately through GitHub's security advisory feature after the repository is published.
