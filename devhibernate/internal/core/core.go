package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vtino17/devhibernate/internal/config"
	"github.com/vtino17/devhibernate/internal/gitx"
	"github.com/vtino17/devhibernate/internal/model"
	"github.com/vtino17/devhibernate/internal/proxy"
)

type App struct {
	Out io.Writer
	Err io.Writer
}
type StartOptions struct{ Name, Base, Branch, Note string }
type DeleteOptions struct {
	Name                            string
	Force, KeepBranch, DeleteBranch bool
}

func New(out, err io.Writer) *App { return &App{Out: out, Err: err} }
func cwdRoot() (string, error) {
	wd, e := os.Getwd()
	if e != nil {
		return "", e
	}
	return gitx.RepoRoot(wd)
}
func (a *App) Init() error {
	root, e := cwdRoot()
	if e != nil {
		return e
	}
	project := filepath.Base(root)
	if e = config.WriteDefault(root, project); e != nil {
		return e
	}
	p := filepath.Join(root, ".gitignore")
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), ".devhibernate/") {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if e != nil {
			return e
		}
		defer f.Close()
		if len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
			_, _ = f.WriteString("\n")
		}
		_, e = f.WriteString(".devhibernate/\n")
		if e != nil {
			return e
		}
	}
	fmt.Fprintf(a.Out, "Created %s\n", filepath.Join(root, config.FileName))
	return nil
}
func worktreePath(root, slug string) (string, error) {
	h, e := proxy.Home()
	if e != nil {
		return "", e
	}
	return filepath.Join(h, "worktrees", model.RepoID(root), slug), nil
}
func owner(root, slug string) string { return model.RepoID(root) + ":" + slug }
