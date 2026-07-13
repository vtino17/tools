package core

import (
	"bytes"
	"encoding/json"
	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/proc"
	"github.com/vtino17/devhibernate/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	repo := fixture(t)
	t.Setenv("DEVHIBERNATE_HOME", filepath.Join(t.TempDir(), "home"))
	t.Setenv("DEVHIBERNATE_DISABLE_PROXY", "1")
	old, _ := os.Getwd()
	_ = os.Chdir(repo)
	defer os.Chdir(old)
	var out, er bytes.Buffer
	a := New(&out, &er)
	if e := a.Start(StartOptions{Name: "Feature A", Note: "Implement lifecycle"}); e != nil {
		t.Fatalf("%v %s", e, er.String())
	}
	s := state(t, repo)
	c := s.Capsules["feature-a"]
	if c.Status != model.StatusRunning || len(c.Services) != 1 || !proc.IsRunning(c.Services[0].PID) {
		t.Fatalf("bad start %#v", c)
	}
	defer func() {
		x := state(t, repo)
		if x.Capsules["feature-a"] != nil {
			_ = a.Delete(DeleteOptions{Name: "feature-a", Force: true, DeleteBranch: true})
		}
	}()
	if e := a.Pause("feature-a"); e != nil {
		t.Fatal(e)
	}
	if state(t, repo).Capsules["feature-a"].Status != model.StatusPaused {
		t.Fatal("not paused")
	}
	if e := a.Resume("feature-a"); e != nil {
		t.Fatal(e)
	}
	if e := a.Check("feature-a", []string{"printf", "check-ok"}); e != nil {
		t.Fatal(e)
	}
	if e := a.Note("feature-a", "Next: add tests"); e != nil {
		t.Fatal(e)
	}
	if e := a.Handoff("feature-a", ""); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(repo, ".devhibernate", "handoffs", "feature-a.md"))
	if e != nil || !strings.Contains(string(b), "Next: add tests") {
		t.Fatal(e)
	}
	if e := a.Pause("feature-a"); e != nil {
		t.Fatal(e)
	}
	if e := a.Delete(DeleteOptions{Name: "feature-a", Force: true, DeleteBranch: true}); e != nil {
		t.Fatal(e)
	}
	if state(t, repo).Capsules["feature-a"] != nil {
		t.Fatal("not deleted")
	}
}
func TestDirtyDeleteRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	repo := fixture(t)
	t.Setenv("DEVHIBERNATE_HOME", filepath.Join(t.TempDir(), "home"))
	t.Setenv("DEVHIBERNATE_DISABLE_PROXY", "1")
	old, _ := os.Getwd()
	_ = os.Chdir(repo)
	defer os.Chdir(old)
	a := New(&bytes.Buffer{}, &bytes.Buffer{})
	if e := a.Start(StartOptions{Name: "dirty"}); e != nil {
		t.Fatal(e)
	}
	c := state(t, repo).Capsules["dirty"]
	if e := os.WriteFile(filepath.Join(c.Worktree, "dirty.txt"), []byte("x"), 0644); e != nil {
		t.Fatal(e)
	}
	_ = a.Pause("dirty")
	if e := a.Delete(DeleteOptions{Name: "dirty"}); e == nil {
		t.Fatal("expected refusal")
	}
	if _, e := os.Stat(filepath.Join(c.Worktree, "dirty.txt")); e != nil {
		t.Fatal("dirty file lost")
	}
	if e := a.Delete(DeleteOptions{Name: "dirty", Force: true, DeleteBranch: true}); e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T) string {
	r := t.TempDir()
	run(t, r, "git", "init", "-b", "main")
	run(t, r, "git", "config", "user.name", "Test")
	run(t, r, "git", "config", "user.email", "t@example.com")
	c := config.Config{Version: 1, Project: "fixture", DefaultBase: "main", ProxyPort: 7777, Services: []config.Service{{Name: "worker", Command: "while true; do sleep 1; done", Health: &config.HealthCheck{Type: "none"}}}}
	b, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(filepath.Join(r, config.FileName), append(b, '\n'), 0644)
	_ = os.WriteFile(filepath.Join(r, "README.md"), []byte("fixture\n"), 0644)
	run(t, r, "git", "add", ".")
	run(t, r, "git", "commit", "-m", "initial")
	return r
}
func run(t *testing.T, d, n string, a ...string) {
	c := exec.Command(n, a...)
	c.Dir = d
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("%s %v: %v %s", n, a, e, b)
	}
}
func state(t *testing.T, r string) *model.ProjectState {
	s, e := store.Load(r)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
