# AI Agent Build Specification

This document translates the product into executable work packages. It is deliberately explicit so a coding agent can implement changes without guessing hidden requirements.

## 1. Canonical objective

Build and maintain a deterministic, local-only CLI that converts a development task into a restartable manifest around a Git worktree and service processes.

## 2. Repository map

```text
cmd/devhibernate/main.go          process entrypoint and version injection
internal/cli/cli.go               command grammar and exit-code mapping
internal/core/core.go             lifecycle orchestration
internal/config/config.go         JSON schema and validation
internal/model/model.go           state schema, status, slug, repo ID
internal/store/store.go           atomic persistence
internal/gitx/git.go              Git subprocess operations
internal/proc/*                   OS shell and process-group operations
internal/proxy/proxy.go           routes and loopback reverse proxy
internal/report/report.go         Markdown handoff generation
docs/                             product and engineering contracts
```

## 3. Runtime sequence: start

```text
CLI parse
  -> locate Git root
  -> load + validate config
  -> normalize capsule name
  -> load state
  -> reject duplicate
  -> calculate global worktree path
  -> git worktree add
  -> create capsule log directory
  -> run setup sequentially
  -> for each service:
       allocate port
       build filtered environment
       start process group
       wait for health
       optionally ensure proxy and register route
  -> persist running state atomically
  -> print URLs and PIDs
```

### Start acceptance matrix

| Situation | Required result |
|---|---|
| invalid JSON | fail before Git mutation |
| duplicate service name | fail before Git mutation |
| duplicate capsule | fail before Git mutation |
| worktree path exists | fail before Git mutation |
| setup command fails | remove worktree, show setup log |
| second service fails | terminate first service |
| health timeout | terminate service, preserve failed capsule/worktree |
| state save fails | terminate services and remove worktree |

## 4. Runtime sequence: pause

```text
load capsule
  -> if already paused, succeed idempotently
  -> stop every service process group
  -> remove all routes for repo-id:capsule-slug
  -> zero PIDs
  -> persist paused status
```

Pause must not run Git commands that modify the worktree.

## 5. Runtime sequence: resume

```text
load capsule
  -> reload latest config
  -> remove stale routes
  -> allocate new ports
  -> start + health-check services
  -> register routes
  -> replace runtime service list
  -> persist running status
```

Resume does not rerun setup.

## 6. Data contracts

### `devhibernate.json`

Config version `1` is the only accepted version. Unknown JSON fields are currently tolerated by Go's decoder; changing to strict decoding is a future breaking consideration.

### `.devhibernate/state.json`

State is internal and not intended for manual editing. New fields must be backward-compatible. Removing or changing field meaning requires a state version migration.

## 7. Security acceptance

An agent changing environment logic must prove:

- an unlisted secret variable is absent from the child process
- a listed variable is present at runtime
- its value is absent from `state.json`
- its value is absent from handoff Markdown
- its value is absent from normal CLI output

An agent changing deletion logic must prove a dirty worktree survives normal deletion.

## 8. Testing layers

### Unit

Pure behavior: slug, config validation, state save/load, route selection, report formatting.

### Integration

Real Git and real process group lifecycle in a temporary directory.

### Manual smoke

Build the binary, create a fixture repository, run every public lifecycle command, inspect processes/state/report, and clean all artifacts.

### CI

Run on Ubuntu and macOS when practical. Windows is build-only until process-tree semantics are implemented and tested.

## 9. Work packages after v0.1

### WP-01 Cross-process lock

Goal: serialize state and registry mutation.  
Acceptance: two concurrent start commands cannot lose state or duplicate routes.

### WP-02 Runtime reconciliation repair

Goal: persist a safe repair when stored running PIDs are no longer alive.  
Acceptance: a repair command never modifies code and converts inconsistent runtime state into an actionable paused or failed state.

### WP-03 Editor adapter

Goal: optionally open a VS Code workspace and configured files.  
Constraint: no editor state is required for lifecycle correctness.

### WP-04 Docker Compose adapter

Goal: treat a compose project as a restartable service group.  
Constraint: never delete volumes without explicit opt-in.

### WP-05 Handoff import

Goal: allow a teammate to recreate branch/worktree/service setup from a signed manifest.  
Constraint: manifests cannot include secret values or arbitrary hidden commands beyond visible repository config.

## 10. Agent response template

After modifying the repository, report:

```text
Implemented:
- observable behavior

Changed:
- exact files and purpose

Verified:
- commands run and pass/fail result

Limitations:
- remaining unsupported behavior

Risk:
- data loss, process, compatibility, or migration considerations
```
