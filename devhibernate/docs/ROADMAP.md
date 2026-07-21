# Roadmap

## v0.1 — tested local lifecycle

- [x] worktree per task
- [x] branch per task
- [x] restartable service commands
- [x] process-group pause/resume on Unix
- [x] health checks
- [x] dynamic ports
- [x] stable local routes
- [x] notes, logs, checks, handoff
- [x] defensive deletion
- [x] integration test

## v0.2 — reliability

- [ ] cross-process file locking
- [ ] persisted reconciliation/repair command
- [x] transactional cleanup of newly created branches on pre-runtime failure
- [ ] structured event log
- [ ] configurable stop signals and grace periods
- [ ] route-registry lock
- [ ] stronger Windows process-tree management

## v0.3 — daily workflow integrations

- [ ] VS Code workspace opener
- [ ] tmux/zellij adapter
- [ ] URL and file open actions from config
- [ ] GitHub issue/PR metadata attachment
- [ ] shell completion
- [ ] Homebrew/Scoop packages

## v0.4 — runtime adapters

- [ ] Docker Compose lifecycle
- [ ] named volume safety policy
- [ ] local database clone hooks
- [ ] user-defined lifecycle hooks

## v1.0 criteria

- Linux, macOS, and Windows lifecycle tests
- crash-safe locking and recovery
- backward-compatible state migration
- signed release binaries
- reproducible release workflow
- documented plugin/adapter interface
