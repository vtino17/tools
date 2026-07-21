# Test Plan

## Automated verification

Run:

```bash
make verify
```

This executes:

1. `gofmt` verification
2. `go vet ./...`
3. `go test -race ./...`
4. binary build

## Unit cases

### Identity

- spaces and punctuation normalize predictably
- empty symbolic names are rejected
- slug length is bounded

### Configuration

- unsupported version rejected
- missing project rejected
- duplicate service rejected
- empty command rejected
- invalid health type rejected
- omitted proxy/base defaulted

### Persistence

- missing state returns an empty versioned state
- save/load round trip
- interrupted temp files do not replace valid state

### Proxy

- route selected by Host header
- unknown host returns 404
- owner removal preserves unrelated routes
- health endpoint works without route registry

### Reporting

- note and last check included when present
- environment values cannot appear because report model has no environment field
- full diff is not included

## Integration lifecycle

The test `TestCapsuleLifecycleEndToEnd` performs:

1. temporary Git repository initialization
2. initial commit creation
3. real worktree creation
4. real long-running shell process start
5. running-state assertion
6. pause and process termination
7. resume and new process start
8. check command recording
9. note update
10. handoff generation
11. safe pause/delete
12. state removal assertion

## Manual smoke script

```bash
make build
TMP=$(mktemp -d)
cd "$TMP"
git init -b main
git config user.name Smoke
git config user.email smoke@example.com
cat > server.go <<'GO'
package main
import ("fmt"; "net/http"; "os")
func main(){
  http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request){fmt.Fprint(w,"ok")})
  http.ListenAndServe("127.0.0.1:"+os.Getenv("PORT"), nil)
}
GO
cat > devhibernate.json <<'JSON'
{
  "version": 1,
  "project": "smoke",
  "defaultBase": "main",
  "proxyPort": 7777,
  "services": [{
    "name": "web",
    "command": "go run server.go",
    "portEnv": "PORT",
    "expose": true,
    "health": {"type": "http", "path": "/health", "timeoutSeconds": 20}
  }]
}
JSON
git add . && git commit -m initial
/path/to/devhibernate start demo
/path/to/devhibernate check demo -- go test ./...
/path/to/devhibernate pause demo
/path/to/devhibernate resume demo
/path/to/devhibernate where demo
/path/to/devhibernate handoff demo
/path/to/devhibernate pause demo
/path/to/devhibernate delete demo --force --delete-branch
```

## Additional automated safety coverage

The current suite also verifies:

- a second service failure cleans earlier processes and routes
- dirty worktree deletion is refused without `--force`
- the environment is deny-by-default

Still to add:

- setup-command failure branch cleanup regression
- proxy daemon port collision
- concurrent state mutation once locking exists
