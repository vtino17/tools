# Architecture

## 1. System context

```text
Developer terminal
      |
      v
DevHibernate CLI
  |       |        |         |
  v       v        v         v
 Git    Process   State     Proxy
worktree groups   JSON      loopback
```

DevHibernate is intentionally local-first. The CLI is the control plane. Git worktrees hold code; local process groups hold runtime services; JSON state records restart metadata; a small loopback proxy maps stable hostnames to ephemeral ports.

## 2. Storage layout

Repository-local:

```text
<repo>/
├── devhibernate.json          tracked configuration
└── .devhibernate/
    ├── state.json             untracked lifecycle state
    ├── logs/
    │   └── <capsule>/
    └── handoffs/
        └── <capsule>.md
```

Global:

```text
$DEVHIBERNATE_HOME/
├── worktrees/
│   └── <repo-id>/<capsule>/
├── routes.json
├── proxy.pid
└── proxy.log
```

Default global home is `~/.devhibernate`.

## 3. Identity

A display name is normalized to a lowercase slug. The slug is:

- the key in `state.json`
- the worktree directory name
- part of the default branch
- part of local proxy hostnames

Repository identity is the first 12 hex characters of SHA-256 over the absolute repository root. This avoids collisions between repositories using the same capsule name.

## 4. Process model

Each service command is executed through the platform shell. On Unix, it receives a new process group. The persisted PID is the group leader.

Pause sends `SIGTERM` to the negative PID, waits for a grace period, then sends `SIGKILL` if necessary. This is essential because package-manager commands often spawn child servers.

Windows currently performs best-effort termination of the stored process only.

## 5. Environment model

The child environment starts from a strict allowlist of basic process variables. Repository config may add variable names through `passEnv`. Values are copied at runtime but are never written to state or handoff output.

Static `service.env` values are intended only for non-secret committed configuration.

## 6. Port and route model

Every service receives a free loopback port through `portEnv`. Exposed services register:

```text
<capsule>-<service>.localhost -> http://127.0.0.1:<allocated-port>
```

The reverse proxy listens on `127.0.0.1:<proxyPort>`. It reloads the small route registry per request, avoiding a daemon control protocol in the MVP.

## 7. Failure handling

### Start failure before worktree creation

No state is written.

### Setup failure

The new worktree is removed. If DevHibernate created a new task branch for this attempt, that branch is removed as part of cleanup. A branch that existed before the command is preserved.

### Service startup failure

Already-started services are terminated. The capsule is persisted as `failed` with its worktree and `lastError` so the user can inspect logs and recover.

### State write failure after services start

Services are stopped and the newly created worktree is removed to avoid an unmanaged runtime.

### Pause failure

State is not changed until process-stop and route removal operations complete.

## 8. Concurrency limitations

The MVP uses atomic file replacement, but it does not implement a cross-process state lock. Concurrent CLI commands against the same repository may race. This is a documented v0.1 limitation and a priority for v0.2.

## 9. Extension points

Future implementations should add adapters behind existing package boundaries:

- container runtime adapter
- editor adapter
- terminal-session adapter
- database-clone adapter
- file lock/state transaction layer

Do not embed these concerns directly into `internal/cli`.
