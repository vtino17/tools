# DevHibernate

> Pause one coding task and resume another without losing your place.

DevHibernate is a local-first CLI that treats a development task as a durable capsule. Each capsule owns an isolated Git worktree, task branch, service processes, logs, health state, local URLs, checks, notes, and a handoff report.

It does **not** snapshot RAM, containers, editor internals, browser sessions, or secrets. Instead, it stores a small restartable manifest so inactive tasks release CPU and memory while code and context remain available.

## Status

This repository contains a tested MVP. The implemented commands are:

```text
init · start · pause · resume · list · status · note · where
check · logs · handoff · delete · doctor · version
```

## Why

Developers frequently switch between features, reviews, incidents, and hotfixes. A normal branch switch does not preserve running services, ports, logs, test results, or the note explaining what should happen next.

DevHibernate makes this workflow explicit:

```bash
devhibernate start payment-timeout --note "Reproduce retry after gateway timeout"
devhibernate pause payment-timeout
devhibernate start hotfix-login
devhibernate pause hotfix-login
devhibernate resume payment-timeout
devhibernate where payment-timeout
```

## Core behavior

`start`:

1. Locates the current Git repository.
2. Creates a task branch and an isolated worktree.
3. Executes configured setup commands.
4. Allocates free localhost ports.
5. Starts services in separate process groups.
6. Runs optional HTTP or TCP health checks.
7. Registers stable `.localhost` routes for exposed services.
8. Writes lifecycle state outside Git-tracked files.

`pause` stops service process groups and unregisters routes. It does not stash, reset, commit, or delete code.

`resume` starts services again with fresh ports and restores routes.

`handoff` creates a Markdown report containing task metadata, service state, the last recorded check, Git status, diff statistics, recent commits, and the current note. Environment variable values are not included.

## Requirements

- Git 2.30 or newer is recommended.
- Linux or macOS for the complete process-group behavior.
- Windows compiles, but process-tree termination remains best-effort in the MVP.
- No AI API key, daemon installation, database, Node.js runtime, or cloud account is required.

## Install from source

```bash
git clone https://github.com/vtino17/devhibernate.git
cd devhibernate
go build -o devhibernate ./cmd/devhibernate
sudo install devhibernate /usr/local/bin/devhibernate
```

For development:

```bash
make test
make build
```

## Quick start

Inside a Git repository:

```bash
devhibernate init
```

Edit `devhibernate.json`:

```json
{
  "version": 1,
  "project": "my-app",
  "defaultBase": "HEAD",
  "proxyPort": 7777,
  "setup": ["npm install"],
  "passEnv": ["DATABASE_URL"],
  "services": [
    {
      "name": "web",
      "command": "npm run dev",
      "portEnv": "PORT",
      "expose": true,
      "health": {
        "type": "http",
        "path": "/",
        "timeoutSeconds": 30
      }
    }
  ],
  "deleteBranchOnDelete": false
}
```

Then:

```bash
devhibernate start issue-482 --note "Implement payment retry"
devhibernate status issue-482
devhibernate check issue-482 -- npm test
devhibernate pause issue-482
devhibernate resume issue-482
devhibernate handoff issue-482
devhibernate delete issue-482 --delete-branch
```

An exposed service named `web` in capsule `issue-482` is available at:

```text
http://issue-482-web.localhost:7777
```

The proxy starts on demand. Set `DEVHIBERNATE_DISABLE_PROXY=1` to disable it.

## Configuration reference

### Top-level fields

| Field | Required | Description |
|---|---:|---|
| `version` | yes | Must be `1` |
| `project` | yes | Human-readable project name |
| `defaultBase` | no | Base ref for new task branches; defaults to `HEAD` |
| `proxyPort` | no | Shared local reverse-proxy port; defaults to `7777` |
| `setup` | no | Commands executed once after creating a worktree |
| `passEnv` | no | Environment variable names allowed into setup/services |
| `services` | no | Restartable local services |
| `deleteBranchOnDelete` | no | Delete task branch on normal capsule deletion |

### Service fields

| Field | Required | Description |
|---|---:|---|
| `name` | yes | Unique service identifier |
| `command` | yes | Shell command run in the worktree |
| `portEnv` | no | Environment variable receiving the allocated port |
| `expose` | no | Register a stable local hostname through the proxy |
| `workingDir` | no | Relative path inside the worktree |
| `env` | no | Non-secret static environment values committed in config |
| `health.type` | no | `none`, `http`, or `tcp` |
| `health.path` | no | HTTP health path |
| `health.timeoutSeconds` | no | Startup deadline |

## Security model

- Environment variables are denied by default except a small safe process baseline.
- Only names listed in `passEnv` are copied from the parent environment.
- State and handoff reports never serialize environment values.
- `delete` refuses to remove a dirty worktree unless `--force` is supplied.
- Service commands are trusted repository configuration and can execute arbitrary local code.
- The proxy binds only to `127.0.0.1`.

Read [docs/SECURITY.md](docs/SECURITY.md) before enabling DevHibernate on untrusted repositories.

## Documentation

- [Product requirements](docs/PRD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [AI agent build specification](docs/AGENT_BUILD_SPEC.md)
- [State machine](docs/STATE_MACHINE.md)
- [Configuration schema](docs/CONFIGURATION.md)
- [Test plan](docs/TEST_PLAN.md)
- [Security](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Contributing

Read [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md). The acceptance command for every change is:

```bash
make verify
```

## License

Apache License 2.0.
