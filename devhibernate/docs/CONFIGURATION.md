# Configuration

File: `devhibernate.json` at the Git repository root.

## Complete example

```json
{
  "version": 1,
  "project": "storefront",
  "defaultBase": "main",
  "proxyPort": 7777,
  "setup": [
    "npm ci"
  ],
  "passEnv": [
    "DATABASE_URL",
    "REDIS_URL"
  ],
  "services": [
    {
      "name": "api",
      "command": "npm run dev:api",
      "portEnv": "API_PORT",
      "expose": true,
      "workingDir": "apps/api",
      "env": {
        "LOG_LEVEL": "debug"
      },
      "health": {
        "type": "http",
        "path": "/health",
        "timeoutSeconds": 30
      }
    },
    {
      "name": "worker",
      "command": "npm run dev:worker",
      "health": {
        "type": "none"
      }
    }
  ],
  "open": {
    "files": [],
    "urls": []
  },
  "deleteBranchOnDelete": false
}
```

## Environment policy

DevHibernate does not pass the complete parent environment. It passes a basic runtime allowlist such as `PATH`, `HOME`, temporary-directory variables, locale, and terminal variables. Add required variable **names** to `passEnv`.

Do not put credentials in `service.env`; that object is committed configuration.

## Port behavior

A free port is allocated on every start and resume. It is provided through `portEnv`. If absent, the default name is derived from the service, such as `PAYMENT_API_PORT`.

A service must bind the given port. Hard-coded ports defeat isolation and may cause health-check failure.

## Health checks

### none

Wait briefly and ensure the process did not exit immediately.

### tcp

Attempt a TCP connection to the allocated port until timeout.

### http

Send a GET request to the configured path. Status codes from 200 through 499 count as reachable; 5xx and connection errors retry until timeout.

## Shell semantics

Commands run with `/bin/sh -lc` on Unix and `cmd /C` on Windows. Repository authors are responsible for command portability.
