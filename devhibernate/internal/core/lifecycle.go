package core

import (
	"fmt"
	"sort"
	"time"

	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/gitx"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/proc"
	"github.com/vtino17/devhibernate/internal/store"
)

func load(name string) (string, *model.ProjectState, *model.Capsule, error) {
	root, e := cwdRoot()
	if e != nil {
		return "", nil, nil, e
	}
	slug, e := model.ValidateCapsuleName(name)
	if e != nil {
		return "", nil, nil, e
	}
	s, e := store.Load(root)
	if e != nil {
		return "", nil, nil, e
	}
	c := s.Capsules[slug]
	if c == nil {
		return "", nil, nil, fmt.Errorf("capsule %q not found", slug)
	}
	return root, s, c, nil
}
func (a *App) Pause(name string) error {
	root, s, c, e := load(name)
	if e != nil {
		return e
	}
	if c.Status == model.StatusPaused {
		fmt.Fprintln(a.Out, "Already paused")
		return nil
	}
	a.stopServices(root, c)
	now := time.Now().UTC()
	c.Status = model.StatusPaused
	c.PausedAt = &now
	c.UpdatedAt = now
	if e = store.Save(root, s); e != nil {
		return e
	}
	fmt.Fprintf(a.Out, "Paused %s\n", c.Slug)
	return nil
}
func (a *App) Resume(name string) error {
	root, s, c, e := load(name)
	if e != nil {
		return e
	}
	if c.Status == model.StatusRunning {
		ok := true
		for _, x := range c.Services {
			if !proc.IsRunning(x.PID) {
				ok = false
			}
		}
		if ok {
			fmt.Fprintln(a.Out, "Already running")
			return nil
		}
	}
	cfg, e := config.Load(root)
	if e != nil {
		return e
	}
	ss, e := a.startServices(root, c, cfg)
	now := time.Now().UTC()
	c.UpdatedAt = now
	c.ResumedAt = &now
	if e != nil {
		c.Status = model.StatusFailed
		c.LastError = e.Error()
		c.Services = ss
		_ = store.Save(root, s)
		return e
	}
	c.Status = model.StatusRunning
	c.LastError = ""
	c.Services = ss
	if e = store.Save(root, s); e != nil {
		a.stopServices(root, c)
		return e
	}
	fmt.Fprintf(a.Out, "Resumed %s\n", c.Slug)
	return nil
}
func (a *App) List() error {
	root, e := cwdRoot()
	if e != nil {
		return e
	}
	s, e := store.Load(root)
	if e != nil {
		return e
	}
	keys := make([]string, 0, len(s.Capsules))
	for k := range s.Capsules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		fmt.Fprintln(a.Out, "No capsules")
		return nil
	}
	for _, k := range keys {
		c := s.Capsules[k]
		status := c.Status
		if status == model.StatusRunning {
			for _, x := range c.Services {
				if !proc.IsRunning(x.PID) {
					status = model.StatusFailed
				}
			}
		}
		fmt.Fprintf(a.Out, "%-24s %-8s %s\n", c.Slug, status, c.Branch)
	}
	return nil
}
func (a *App) Status(name string) error {
	if name == "" {
		return a.List()
	}
	_, _, c, e := load(name)
	if e != nil {
		return e
	}
	fmt.Fprintf(a.Out, "Name: %s\nSlug: %s\nStatus: %s\nBranch: %s\nWorktree: %s\nNote: %s\n", c.Name, c.Slug, c.Status, c.Branch, c.Worktree, c.Note)
	for _, x := range c.Services {
		fmt.Fprintf(a.Out, "Service %s PID=%d port=%d url=%s log=%s\n", x.Name, x.PID, x.Port, x.URL, x.LogPath)
	}
	return nil
}
func (a *App) Note(name, text string) error {
	root, s, c, e := load(name)
	if e != nil {
		return e
	}
	c.Note = text
	c.UpdatedAt = time.Now().UTC()
	return store.Save(root, s)
}
func (a *App) Where(name string) error {
	_, _, c, e := load(name)
	if e != nil {
		return e
	}
	g := gitx.Summary(c.Worktree)
	fmt.Fprintf(a.Out, "Capsule: %s (%s)\nBranch: %s\nNote: %s\nLast commit: %s\n", c.Name, c.Status, c.Branch, c.Note, g["lastCommit"])
	if c.LastCheck != nil {
		fmt.Fprintf(a.Out, "Last check: %s (exit %d)\n", c.LastCheck.Command, c.LastCheck.ExitCode)
	}
	if g["status"] != "" {
		fmt.Fprintf(a.Out, "Changed files:\n%s\n", g["status"])
	}
	if c.Status == model.StatusPaused {
		fmt.Fprintf(a.Out, "Next: devhibernate resume %s\n", c.Slug)
	}
	return nil
}
