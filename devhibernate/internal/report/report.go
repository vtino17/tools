package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vtino17/devhibernate/internal/gitx"
	"github.com/vtino17/devhibernate/internal/model"
)

func Build(c *model.Capsule) string {
	summary := gitx.Summary(c.Worktree)
	var b strings.Builder
	fmt.Fprintf(&b, "# DevHibernate Handoff: %s\n\n", c.Name)
	fmt.Fprintf(&b, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "## Capsule\n\n- Status: `%s`\n- Branch: `%s`\n- Base: `%s`\n- Worktree: `%s`\n", c.Status, c.Branch, c.Base, c.Worktree)
	if c.Note != "" {
		fmt.Fprintf(&b, "- Current note: %s\n", c.Note)
	}
	if c.LastError != "" {
		fmt.Fprintf(&b, "- Last error: `%s`\n", c.LastError)
	}
	fmt.Fprintln(&b, "\n## Services")
	if len(c.Services) == 0 {
		fmt.Fprintln(&b, "\nNo services are currently running.")
	}
	for _, svc := range c.Services {
		fmt.Fprintf(&b, "\n- **%s** — PID `%d`, port `%d`", svc.Name, svc.PID, svc.Port)
		if svc.URL != "" {
			fmt.Fprintf(&b, ", URL: %s", svc.URL)
		}
		fmt.Fprintf(&b, "\n  - Command: `%s`\n  - Log: `%s`\n", svc.Command, svc.LogPath)
	}
	if c.LastCheck != nil {
		fmt.Fprintln(&b, "\n## Last Check")
		fmt.Fprintf(&b, "\n- Command: `%s`\n- Exit code: `%d`\n- Finished: `%s`\n- Log: `%s`\n", c.LastCheck.Command, c.LastCheck.ExitCode, c.LastCheck.FinishedAt.Format(time.RFC3339), c.LastCheck.LogPath)
	}
	fmt.Fprintln(&b, "\n## Git Status")
	if summary["status"] == "" {
		fmt.Fprintln(&b, "\nWorking tree is clean.")
	} else {
		fmt.Fprintf(&b, "\n```text\n%s\n```\n", summary["status"])
	}
	fmt.Fprintln(&b, "\n## Diff Summary")
	if summary["diffstat"] == "" {
		fmt.Fprintln(&b, "\nNo unstaged diff summary.")
	} else {
		fmt.Fprintf(&b, "\n```text\n%s\n```\n", summary["diffstat"])
	}
	fmt.Fprintln(&b, "\n## Recent Commits")
	fmt.Fprintf(&b, "\n```text\n%s\n```\n", summary["commits"])
	fmt.Fprintln(&b, "\n## Resume")
	fmt.Fprintf(&b, "\n```bash\ndevhibernate resume %s\n```\n", c.Slug)
	fmt.Fprintln(&b, "\n## Privacy")
	fmt.Fprintln(&b, "\nThis report contains command names, paths, Git metadata, and service URLs. DevHibernate never serializes environment variable values into state or handoff reports.")
	return b.String()
}

func Write(c *model.Capsule, output string) (string, error) {
	if output == "" {
		return "", fmt.Errorf("output path is required")
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(c.Worktree, output)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(output, []byte(Build(c)), 0o644); err != nil {
		return "", err
	}
	return output, nil
}
