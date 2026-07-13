# Capsule State Machine

## Persisted statuses

- `running`: services were started successfully; all configured service PIDs are expected to be alive.
- `paused`: no managed service should be running; branch, worktree, logs, and context remain.
- `failed`: startup or resume failed, or runtime health is inconsistent.

## Diagram

```text
                    start success
             +--------------------------+
             |                          v
       [nonexistent]                [running]
             |                          |
             | start runtime failure    | pause
             v                          v
          [failed] <--------------- [paused]
             |       resume failure      |
             +-----------+---------------+
                         |
                    resume success
                         v
                     [running]

Any persisted state --delete succeeds--> [nonexistent]
```

## Reconciliation

`list` reports a running capsule as failed when one or more stored service PIDs are no longer alive. The MVP does not automatically persist that reconciled status; `doctor` reports the inconsistency. A later release may add a repair command.

## Idempotency

- Pausing a paused capsule succeeds without mutation.
- Resuming a healthy running capsule succeeds without starting duplicates.
- Starting an existing capsule fails and points to lifecycle commands.
- Deleting a missing capsule fails.
