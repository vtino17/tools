package core

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/proc"
	"github.com/vtino17/devhibernate/internal/proxy"
	"github.com/vtino17/devhibernate/internal/store"
)

func filteredEnv(cfg config.Config, svc *config.Service, port int) []string {
	allow := map[string]bool{"PATH": true, "HOME": true, "USER": true, "SHELL": true, "TMPDIR": true, "TEMP": true, "TMP": true, "LANG": true, "LC_ALL": true, "TERM": true, "SYSTEMROOT": true, "COMSPEC": true}
	for _, n := range cfg.PassEnv {
		allow[n] = true
	}
	m := map[string]string{}
	for _, kv := range os.Environ() {
		p := strings.SplitN(kv, "=", 2)
		if len(p) == 2 && allow[p[0]] {
			m[p[0]] = p[1]
		}
	}
	if svc != nil {
		for k, v := range svc.Env {
			m[k] = v
		}
		pe := svc.PortEnv
		if pe == "" {
			pe = strings.ToUpper(strings.ReplaceAll(svc.Name, "-", "_")) + "_PORT"
		}
		m[pe] = fmt.Sprint(port)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
func allocatePort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func (a *App) startServices(root string, c *model.Capsule, cfg config.Config) ([]model.ServiceRuntime, error) {
	_ = proxy.RemoveOwner(owner(root, c.Slug))
	var out []model.ServiceRuntime
	for _, svc := range cfg.Services {
		port, e := allocatePort()
		if e != nil {
			a.stopRuntime(root, c.Slug, out)
			return out, e
		}
		dir := c.Worktree
		if svc.WorkingDir != "" {
			dir = filepath.Join(dir, svc.WorkingDir)
		}
		log := filepath.Join(store.LogsDir(root), c.Slug, svc.Name+".log")
		if e = os.MkdirAll(filepath.Dir(log), 0755); e != nil {
			a.stopRuntime(root, c.Slug, out)
			return out, e
		}
		f, e := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if e != nil {
			a.stopRuntime(root, c.Slug, out)
			return out, e
		}
		cmd := proc.ShellCommand(svc.Command)
		cmd.Dir = dir
		cmd.Env = filteredEnv(cfg, &svc, port)
		cmd.Stdout = f
		cmd.Stderr = f
		proc.Configure(cmd)
		if e = cmd.Start(); e != nil {
			f.Close()
			a.stopRuntime(root, c.Slug, out)
			return out, fmt.Errorf("start service %s: %w", svc.Name, e)
		}
		_ = f.Close()
		rt := model.ServiceRuntime{Name: svc.Name, Command: svc.Command, Port: port, PortEnv: svc.PortEnv, PID: cmd.Process.Pid, LogPath: log, StartedAt: time.Now().UTC()}
		out = append(out, rt)
		if e = waitHealth(svc, port, cmd.Process.Pid); e != nil {
			a.stopRuntime(root, c.Slug, out)
			return out, fmt.Errorf("service %s failed health check; see %s: %w", svc.Name, log, e)
		}
		if svc.Expose {
			if e = proxy.EnsureDaemon(cfg.ProxyPort); e != nil {
				a.stopRuntime(root, c.Slug, out)
				return out, e
			}
			host := c.Slug + "-" + model.Slugify(svc.Name) + ".localhost"
			url := fmt.Sprintf("http://%s:%d", host, cfg.ProxyPort)
			if e = proxy.Register(host, fmt.Sprintf("http://127.0.0.1:%d", port), owner(root, c.Slug)); e != nil {
				a.stopRuntime(root, c.Slug, out)
				return out, e
			}
			out[len(out)-1].Host = host
			out[len(out)-1].URL = url
		}
	}
	return out, nil
}
func waitHealth(s config.Service, port, pid int) error {
	kind := "none"
	timeout := 30 * time.Second
	if s.Health != nil {
		if s.Health.Type != "" {
			kind = s.Health.Type
		}
		if s.Health.TimeoutSeconds > 0 {
			timeout = time.Duration(s.Health.TimeoutSeconds) * time.Second
		}
	}
	if kind == "none" {
		time.Sleep(250 * time.Millisecond)
		if !proc.IsRunning(pid) {
			return fmt.Errorf("process exited immediately")
		}
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !proc.IsRunning(pid) {
			return fmt.Errorf("process exited")
		}
		if kind == "tcp" {
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
			if e == nil {
				c.Close()
				return nil
			}
		} else {
			path := "/"
			if s.Health != nil && s.Health.Path != "" {
				path = s.Health.Path
			}
			cl := http.Client{Timeout: 500 * time.Millisecond}
			r, e := cl.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
			if e == nil {
				r.Body.Close()
				if r.StatusCode < 500 {
					return nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", timeout)
}
func (a *App) stopRuntime(root, slug string, ss []model.ServiceRuntime) {
	for i := len(ss) - 1; i >= 0; i-- {
		_ = proc.StopGroup(ss[i].PID, 2*time.Second)
	}
	_ = proxy.RemoveOwner(owner(root, slug))
}
func (a *App) stopServices(root string, c *model.Capsule) {
	a.stopRuntime(root, c.Slug, c.Services)
	for i := range c.Services {
		c.Services[i].PID = 0
	}
}
