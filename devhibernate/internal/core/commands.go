package core

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/gitx"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/proc"
	"github.com/vtino17/devhibernate/internal/proxy"
	"github.com/vtino17/devhibernate/internal/report"
	"github.com/vtino17/devhibernate/internal/store"
)

func runCommand(dir, command string, env []string, log string, terminal io.Writer) error {
	f, e := os.OpenFile(log, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	c := proc.ShellCommand(command)
	c.Dir = dir
	c.Env = env
	if terminal != nil {
		c.Stdout = io.MultiWriter(f, terminal)
		c.Stderr = io.MultiWriter(f, terminal)
	} else {
		c.Stdout = f
		c.Stderr = f
	}
	return c.Run()
}
func (a *App) Check(name string, args []string) error {
	root, s, c, e := load(name)
	if e != nil {
		return e
	}
	if len(args) == 0 {
		return fmt.Errorf("check command is required")
	}
	cmd := strings.Join(args, " ")
	log := filepath.Join(store.LogsDir(root), c.Slug, "check-"+time.Now().UTC().Format("20060102T150405")+".log")
	start := time.Now().UTC()
	e = runCommand(c.Worktree, cmd, filteredEnv(config.Config{}, nil, 0), log, a.Out)
	finish := time.Now().UTC()
	code := 0
	if e != nil {
		code = 1
		if x, ok := e.(*exec.ExitError); ok {
			code = x.ExitCode()
		}
	}
	c.LastCheck = &model.CheckResult{Command: cmd, ExitCode: code, LogPath: log, StartedAt: start, FinishedAt: finish}
	c.UpdatedAt = finish
	if se := store.Save(root, s); se != nil {
		return se
	}
	return e
}
func (a *App) Handoff(name, out string) error {
	root, _, c, e := load(name)
	if e != nil {
		return e
	}
	if out == "" {
		out = filepath.Join(root, ".devhibernate", "handoffs", c.Slug+".md")
	}
	p, e := report.Write(c, out)
	if e == nil {
		fmt.Fprintln(a.Out, p)
	}
	return e
}
func (a *App) Logs(name, service string, tail int) error {
	_, _, c, e := load(name)
	if e != nil {
		return e
	}
	var paths []string
	for _, x := range c.Services {
		if service == "" || service == x.Name {
			paths = append(paths, x.LogPath)
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("no matching service logs")
	}
	for _, p := range paths {
		lines, e := tailFile(p, tail)
		if e != nil {
			return e
		}
		fmt.Fprintf(a.Out, "==> %s <==\n%s", p, lines)
	}
	return nil
}
func tailFile(path string, n int) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if e = s.Err(); e != nil {
		return "", e
	}
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n", nil
}
func (a *App) Delete(o DeleteOptions) error {
	root, s, c, e := load(o.Name)
	if e != nil {
		return e
	}
	if c.Status == model.StatusRunning {
		a.stopServices(root, c)
	}
	dirty, status, e := gitx.IsDirty(c.Worktree)
	if e != nil {
		return e
	}
	if dirty && !o.Force {
		return fmt.Errorf("worktree has uncommitted changes; use --force to discard:\n%s", status)
	}
	if e = gitx.RemoveWorktree(root, c.Worktree, o.Force); e != nil {
		return e
	}
	cfg, _ := config.Load(root)
	if !o.KeepBranch && (o.DeleteBranch || cfg.DeleteBranch) {
		if e = gitx.DeleteBranch(root, c.Branch); e != nil {
			return e
		}
	}
	delete(s.Capsules, c.Slug)
	if e = store.Save(root, s); e != nil {
		return e
	}
	fmt.Fprintf(a.Out, "Deleted %s\n", c.Slug)
	return nil
}
func (a *App) Doctor() error {
	root, e := cwdRoot()
	if e != nil {
		return e
	}
	cfg, e := config.Load(root)
	if e != nil {
		return e
	}
	s, e := store.Load(root)
	if e != nil {
		return e
	}
	problems := 0
	for _, c := range s.Capsules {
		if _, e = os.Stat(c.Worktree); e != nil {
			fmt.Fprintf(a.Err, "missing worktree: %s\n", c.Worktree)
			problems++
		}
		if c.Status == model.StatusRunning {
			for _, x := range c.Services {
				if !proc.IsRunning(x.PID) {
					fmt.Fprintf(a.Err, "dead service %s/%s pid=%d\n", c.Slug, x.Name, x.PID)
					problems++
				}
			}
		}
	}
	if cfg.ProxyPort > 0 && os.Getenv("DEVHIBERNATE_DISABLE_PROXY") != "1" && !proxy.IsHealthy(cfg.ProxyPort) {
		fmt.Fprintf(a.Err, "proxy is not running on port %d (it starts on demand)\n", cfg.ProxyPort)
	}
	if problems > 0 {
		return fmt.Errorf("doctor found %d problem(s)", problems)
	}
	fmt.Fprintln(a.Out, "Doctor: healthy")
	return nil
}
func (a *App) ProxyDaemon(port int) error { return proxy.RunDaemon(port) }
