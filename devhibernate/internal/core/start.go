package core

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/gitx"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/store"
)

func (a *App) Start(o StartOptions) error {
	root, e := cwdRoot()
	if e != nil {
		return e
	}
	cfg, e := config.Load(root)
	if e != nil {
		return e
	}
	slug, e := model.ValidateCapsuleName(o.Name)
	if e != nil {
		return e
	}
	state, e := store.Load(root)
	if e != nil {
		return e
	}
	if _, ok := state.Capsules[slug]; ok {
		return fmt.Errorf("capsule %q already exists; use resume/status/delete", slug)
	}
	wt, e := worktreePath(root, slug)
	if e != nil {
		return e
	}
	if _, e = os.Stat(wt); e == nil {
		return fmt.Errorf("worktree path already exists: %s", wt)
	}
	base := o.Base
	if base == "" {
		base = cfg.DefaultBase
	}
	branch := o.Branch
	if branch == "" {
		branch = "devhibernate/" + slug
	}
	branchExisted := gitx.BranchExists(root, branch)
	if e = os.MkdirAll(filepath.Dir(wt), 0755); e != nil {
		return e
	}
	fmt.Fprintf(a.Out, "Creating worktree %s on branch %s...\n", wt, branch)
	if e = gitx.CreateWorktree(root, wt, branch, base); e != nil {
		return e
	}
	created := true
	cleanup := func() {
		if created {
			_ = gitx.RemoveWorktree(root, wt, true)
			if !branchExisted {
				_ = gitx.DeleteBranch(root, branch)
			}
		}
	}
	logDir := filepath.Join(store.LogsDir(root), slug)
	if e = os.MkdirAll(logDir, 0755); e != nil {
		cleanup()
		return e
	}
	for i, cmd := range cfg.Setup {
		log := filepath.Join(logDir, fmt.Sprintf("setup-%02d.log", i+1))
		if e = runCommand(wt, cmd, filteredEnv(cfg, nil, 0), log, nil); e != nil {
			cleanup()
			return fmt.Errorf("setup failed; see %s: %w", log, e)
		}
	}
	now := time.Now().UTC()
	c := &model.Capsule{Name: o.Name, Slug: slug, Status: model.StatusRunning, Branch: branch, Base: base, Worktree: wt, Note: o.Note, CreatedAt: now, UpdatedAt: now}
	services, e := a.startServices(root, c, cfg)
	if e != nil {
		c.Status = model.StatusFailed
		c.LastError = e.Error()
		c.Services = services
		state.Capsules[slug] = c
		if se := store.Save(root, state); se != nil {
			cleanup()
			return fmt.Errorf("start failed: %v; state save failed: %w", e, se)
		}
		created = false
		return e
	}
	c.Services = services
	state.Capsules[slug] = c
	if e = store.Save(root, state); e != nil {
		a.stopServices(root, c)
		cleanup()
		return e
	}
	created = false
	fmt.Fprintf(a.Out, "Capsule %s is running\n", slug)
	for _, s := range services {
		if s.URL != "" {
			fmt.Fprintf(a.Out, "  %s: %s\n", s.Name, s.URL)
		}
	}
	return nil
}
