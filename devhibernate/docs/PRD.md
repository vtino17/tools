# Product Requirements Document

## 1. Product

**Name:** DevHibernate  
**Category:** local developer productivity CLI  
**Tagline:** Pause one coding task and resume another without losing your place.

## 2. Problem

A developer task is larger than a Git branch. It also includes a worktree, running services, allocated ports, logs, test results, local URLs, current hypothesis, and the next action. Switching tasks normally destroys or mixes this context, while leaving every task running consumes memory and CPU.

## 3. Target users

Primary:

- developers handling multiple issues or hotfixes
- maintainers reviewing several pull requests locally
- developers running coding agents in parallel worktrees
- laptop users constrained by RAM and CPU

Secondary:

- technical support engineers reproducing issues
- QA engineers managing multiple local environments
- open-source contributors switching between forks and branches

## 4. Jobs to be done

- “When an urgent issue appears, let me stop my current task without losing its code or context.”
- “When I return, tell me what was running, what last failed, and what I planned to do next.”
- “Let me run two branches without port collisions.”
- “Let me hand a task to another developer without manually writing a long status message.”
- “Do not require cloud services, an API key, or a heavy local model.”

## 5. MVP user stories

### Capsule creation

As a developer, I can create a capsule from the current repository so that I receive an isolated branch and worktree.

Acceptance:

- duplicate capsule identity is rejected
- branch and base can be overridden
- setup commands run once
- startup failure is actionable

### Runtime lifecycle

As a developer, I can pause and resume services so inactive tasks release resources.

Acceptance:

- child processes are stopped on Unix
- code remains untouched
- resume allocates fresh ports
- service health is validated

### Context recovery

As a developer, I can see where I left off.

Acceptance:

- note, last commit, changed files, and last check are displayed
- paused capsules show the exact resume command

### Handoff

As a developer, I can create a safe report for a teammate.

Acceptance:

- report is deterministic Markdown
- it contains no environment values or full source content
- report location is outside the task worktree by default

### Safe deletion

As a developer, I cannot accidentally delete uncommitted work.

Acceptance:

- dirty worktrees block normal deletion
- `--force` is explicit
- `--delete-branch` is explicit and `--keep-branch` overrides branch deletion

## 6. Success metrics after public release

Product metrics:

- installation-to-first-capsule conversion
- capsules started per active user per week
- pause/resume operations per active user
- percentage of capsules with a note or check
- handoff reports generated
- failed cleanup rate

Quality metrics:

- lifecycle integration pass rate across supported OSes
- orphan process incidents
- state corruption incidents
- accidental data-loss reports
- median start/resume duration

## 7. Non-goals for MVP

- remote environments
- memory checkpointing
- container snapshotting
- secret management
- autonomous code generation
- collaboration backend
- IDE-specific state restoration

## 8. Release criteria for v0.1.0

- all documented MVP commands implemented
- standard-library-only Go module
- `go test -race ./...` passes on Linux
- GitHub Actions runs format, vet, test, and build
- security and limitations documented
- manual lifecycle smoke test documented and passed
