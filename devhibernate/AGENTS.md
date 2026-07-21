# AGENTS.md — Source of truth for coding agents

This file is the operational contract for any AI coding agent modifying DevHibernate. Read it before editing code. When this file conflicts with an informal request, stop and surface the conflict instead of silently changing product invariants.

## 1. Product sentence

DevHibernate is a lightweight local CLI that creates an isolated Git worktree per development task, starts restartable local services, releases their resources on pause, restores them on resume, and produces a safe handoff report.

## 2. MVP boundaries

### Implemented and supported

- Local Git repositories.
- One repository state file at `.devhibernate/state.json`.
- Worktrees stored under `$DEVHIBERNATE_HOME/worktrees/<repo-id>/<capsule-slug>`.
- Task branch creation.
- Setup commands executed once when a capsule is created.
- Service process start, health check, pause, and resume.
- HTTP/TCP/none health checks.
- Stable `.localhost` routing through a shared loopback proxy.
- Notes, Git summary, check recorder, logs, and Markdown handoff.
- Defensive deletion of worktrees.
- Linux/macOS complete lifecycle; Windows best-effort process termination.

### Explicitly not implemented

Do not claim or simulate these features unless an issue explicitly adds them with tests and docs:

- RAM snapshots or OS process checkpoint/restore.
- Container filesystem snapshots.
- Automatic database cloning.
- Browser tab restoration.
- Editor tab restoration.
- tmux session restoration.
- Cloud synchronization.
- Team collaboration server.
- Secret storage.
- AI-generated notes or summaries.
- IDE extensions.
- Kubernetes support.

## 3. Non-negotiable invariants

1. **Never alter user code during pause or resume.** No automatic commit, stash, reset, checkout, rebase, or merge.
2. **Never persist environment variable values.** State may store variable names, never values.
3. **Never delete a dirty worktree without explicit `--force`.**
4. **Every running service must belong to its own process group on Unix.** Pause must terminate descendants, not only the shell parent.
5. **State writes must be atomic.** Write a temporary file, sync, close, and rename.
6. **Routes must bind to loopback only.**
7. **A capsule slug is the stable identity.** Display names may be human-friendly; state keys and route owners use slugs.
8. **A command must return non-zero on failure.** Human-readable errors go to stderr.
9. **The CLI must remain usable without network access.**
10. **The core binary must not require external Go modules for the MVP.** Standard library only.

## 4. State machine

Allowed transitions:

```text
nonexistent -> running     start succeeds
nonexistent -> failed      worktree exists but startup failed
running     -> paused      pause succeeds
running     -> failed      service death or startup inconsistency
paused      -> running     resume succeeds
paused      -> failed      resume fails
failed      -> running     resume succeeds
failed      -> paused      user pauses/cleans failed runtime
any         -> nonexistent delete succeeds
```

Do not invent additional persisted statuses without updating:

- `internal/model/model.go`
- `docs/STATE_MACHINE.md`
- tests
- CLI output documentation

## 5. Command contracts

### `init`

Preconditions: current directory is inside a Git repository.

Effects:

- Creates `devhibernate.json` only if absent.
- Adds `.devhibernate/` to `.gitignore` idempotently.
- Never overwrites config.

### `start <name>`

Preconditions:

- Valid config.
- Capsule slug does not exist.
- Worktree target path does not exist.

Effects in order:

1. Create branch/worktree.
2. Create log directory.
3. Run setup commands.
4. Start configured services.
5. Complete health checks.
6. Register proxy routes.
7. Atomically persist running state.

Failure rule: stop any services already started. Preserve a failed capsule only when the worktree was successfully created and runtime startup failed; record `lastError`.

### `pause <name>`

Effects:

- Stop all process groups.
- Remove proxy routes owned by the capsule.
- Keep branch, worktree, logs, note, ports, and last check metadata.
- Set service PIDs to zero.

### `resume <name>`

Effects:

- Load current config from the repository root.
- Allocate new ports.
- Start services and health checks.
- Re-register routes.
- Replace runtime service metadata.

Setup commands do not run again.

### `check <name> -- <command>`

Effects:

- Run inside the capsule worktree.
- Stream stdout/stderr to the terminal and a log file.
- Store command, exit code, timestamps, and log path.
- Return non-zero when the check command fails.

### `handoff <name>`

Must contain:

- Name/status/branch/base/worktree.
- Note and last error when present.
- Runtime service metadata.
- Last check metadata.
- Git status, diff stat, and recent commits.
- Resume command.
- Privacy statement.

Must not contain:

- Environment values.
- Full Git diff.
- File contents.
- Tokens, passwords, cookies, or headers.

### `delete <name>`

- Stop processes and remove routes first.
- Refuse dirty worktree without `--force`.
- Remove worktree before deleting state.
- Branch deletion follows `deleteBranchOnDelete`, `--delete-branch`, and `--keep-branch`. `--force` only bypasses the dirty-worktree guard.

## 6. Package responsibilities

- `cmd/devhibernate`: binary entrypoint only.
- `internal/cli`: argument parsing, help, exit codes.
- `internal/core`: use-case orchestration.
- `internal/config`: config parsing/defaulting/validation.
- `internal/model`: persisted data structures and identity helpers.
- `internal/store`: atomic state persistence.
- `internal/gitx`: Git command adapter.
- `internal/proc`: shell and OS process-group adapter.
- `internal/proxy`: local route registry and reverse proxy.
- `internal/report`: deterministic handoff rendering.

Do not move Git commands into CLI or HTTP routing into core.

## 7. Error-handling rules

- Wrap errors with the failed operation and relevant entity.
- Do not swallow cleanup errors silently when they can cause data loss.
- Cleanup errors after a primary failure may be logged as warnings.
- Never expose environment values in errors.
- Health-check failures must mention the service and log path.

## 8. Testing requirements

Every feature change needs the smallest relevant tests plus an end-to-end lifecycle regression when lifecycle behavior changes.

Required verification:

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build ./cmd/devhibernate
```

The existing integration test must continue to perform real operations:

- create a temporary Git repository
- create a worktree
- launch a long-running process
- pause
- resume
- record a check
- generate handoff
- delete and clean state

Do not replace it with mocks.

## 9. Change workflow for agents

1. Restate the requested behavior as observable acceptance criteria.
2. Identify affected invariants and command contracts.
3. Add or update tests before/with implementation.
4. Make the smallest coherent change.
5. Run `make verify`.
6. Update README/docs when user behavior changes.
7. Summarize exact files changed, tests run, and known limitations.

## 10. Definition of done

A change is done only when:

- behavior is implemented, not stubbed
- errors are actionable
- state migration concerns are handled
- unit/integration tests pass
- `go vet` passes
- binary builds
- CLI help and docs match implementation
- no future feature is described as currently available
