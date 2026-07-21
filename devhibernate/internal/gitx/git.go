package gitx

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func Run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("git %s: %s", strings.Join(args, " "), message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func RepoRoot(dir string) (string, error) {
	out, err := Run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("not inside a Git repository: %w", err)
	}
	return filepath.Clean(out), nil
}

func CurrentBranch(root string) string {
	out, err := Run(root, "branch", "--show-current")
	if err != nil || out == "" {
		return "HEAD"
	}
	return out
}

func BranchExists(root, branch string) bool {
	cmd := exec.Command("git", "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
	cmd.Dir = root
	return cmd.Run() == nil
}

func CreateWorktree(root, path, branch, base string) error {
	if BranchExists(root, branch) {
		_, err := Run(root, "worktree", "add", path, branch)
		return err
	}
	if base == "" {
		base = "HEAD"
	}
	_, err := Run(root, "worktree", "add", "-b", branch, path, base)
	return err
}

func RemoveWorktree(root, path string, force bool) error {
	args := []string{"worktree", "remove"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, path)
	_, err := Run(root, args...)
	return err
}

func DeleteBranch(root, branch string) error {
	_, err := Run(root, "branch", "-D", branch)
	return err
}

func IsDirty(worktree string) (bool, string, error) {
	out, err := Run(worktree, "status", "--short")
	if err != nil {
		return false, "", err
	}
	return out != "", out, nil
}

func Summary(worktree string) map[string]string {
	result := map[string]string{}
	if out, err := Run(worktree, "status", "--short"); err == nil {
		result["status"] = out
	}
	if out, err := Run(worktree, "diff", "--stat"); err == nil {
		result["diffstat"] = out
	}
	if out, err := Run(worktree, "log", "-5", "--oneline", "--decorate"); err == nil {
		result["commits"] = out
	}
	if out, err := Run(worktree, "log", "-1", "--format=%h %s (%ar)"); err == nil {
		result["lastCommit"] = out
	}
	return result
}
