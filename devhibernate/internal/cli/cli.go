package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vtino17/devhibernate/internal/core"
)

func Run(args []string, version string, out, errOut io.Writer) int {
	if len(args) == 0 {
		printHelp(out)
		return 0
	}
	app := core.New(out, errOut)
	command := args[0]
	var err error

	switch command {
	case "help", "-h", "--help":
		printHelp(out)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(out, "devhibernate %s\n", version)
		return 0
	case "init":
		err = app.Init()
	case "start":
		err = runStart(app, args[1:])
	case "pause":
		err = requireOne(args[1:], "pause", app.Pause)
	case "resume":
		err = requireOne(args[1:], "resume", app.Resume)
	case "list":
		err = app.List()
	case "status":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		err = app.Status(name)
	case "note":
		if len(args) < 3 {
			err = fmt.Errorf("usage: devhibernate note <name> <text>")
		} else {
			err = app.Note(args[1], strings.Join(args[2:], " "))
		}
	case "where":
		err = requireOne(args[1:], "where", app.Where)
	case "check":
		err = runCheck(app, args[1:])
	case "handoff":
		err = runHandoff(app, args[1:])
	case "logs":
		err = runLogs(app, args[1:])
	case "delete":
		err = runDelete(app, args[1:])
	case "doctor":
		err = app.Doctor()
	case "__proxy-daemon":
		err = runProxyDaemon(app, args[1:])
	default:
		fmt.Fprintf(errOut, "unknown command %q\n\n", command)
		printHelp(errOut)
		return 2
	}
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return 1
	}
	return 0
}

func runStart(app *core.App, args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	base := fs.String("base", "", "base ref")
	branch := fs.String("branch", "", "branch name")
	note := fs.String("note", "", "current task note")
	ordered := reorderFlags(args, map[string]bool{"--base": true, "--branch": true, "--note": true})
	if err := fs.Parse(ordered); err != nil {
		return fmt.Errorf("usage: devhibernate start <name> [--base ref] [--branch branch] [--note text]: %w", err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: devhibernate start <name> [--base ref] [--branch branch] [--note text]")
	}
	return app.Start(core.StartOptions{Name: fs.Arg(0), Base: *base, Branch: *branch, Note: *note})
}

func runCheck(app *core.App, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: devhibernate check <name> -- <command>")
	}
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator != 1 || separator == len(args)-1 {
		return fmt.Errorf("usage: devhibernate check <name> -- <command>")
	}
	return app.Check(args[0], args[separator+1:])
}

func runHandoff(app *core.App, args []string) error {
	fs := flag.NewFlagSet("handoff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "output path")
	ordered := reorderFlags(args, map[string]bool{"--output": true})
	if err := fs.Parse(ordered); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: devhibernate handoff <name> [--output path]")
	}
	return app.Handoff(fs.Arg(0), *output)
}

func runLogs(app *core.App, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tail := fs.Int("tail", 100, "number of lines")
	ordered := reorderFlags(args, map[string]bool{"--tail": true})
	if err := fs.Parse(ordered); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("usage: devhibernate logs <name> [service] [--tail n]")
	}
	service := ""
	if fs.NArg() == 2 {
		service = fs.Arg(1)
	}
	return app.Logs(fs.Arg(0), service, *tail)
}

func runDelete(app *core.App, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "discard uncommitted changes")
	keepBranch := fs.Bool("keep-branch", false, "keep task branch")
	deleteBranch := fs.Bool("delete-branch", false, "delete task branch after removing worktree")
	ordered := reorderFlags(args, map[string]bool{})
	if err := fs.Parse(ordered); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: devhibernate delete <name> [--force] [--delete-branch] [--keep-branch]")
	}
	return app.Delete(core.DeleteOptions{Name: fs.Arg(0), Force: *force, KeepBranch: *keepBranch, DeleteBranch: *deleteBranch})
}

func runProxyDaemon(app *core.App, args []string) error {
	port := 7777
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			parsed, err := strconv.Atoi(args[i+1])
			if err != nil {
				return err
			}
			port = parsed
			i++
		}
	}
	return app.ProxyDaemon(port)
}

func requireOne(args []string, command string, fn func(string) error) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: devhibernate %s <name>", command)
	}
	return fn(args[0])
}

func reorderFlags(args []string, valueFlags map[string]bool) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			flags = append(flags, arg)
			name := arg
			if idx := strings.Index(arg, "="); idx >= 0 {
				name = arg[:idx]
			}
			if valueFlags[name] && !strings.Contains(arg, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, `DevHibernate — pause one coding task and resume another without losing your place.

Usage:
  devhibernate init
  devhibernate start <name> [--base ref] [--branch branch] [--note text]
  devhibernate pause <name>
  devhibernate resume <name>
  devhibernate list
  devhibernate status [name]
  devhibernate note <name> <text>
  devhibernate where <name>
  devhibernate check <name> -- <command>
  devhibernate logs <name> [service] [--tail n]
  devhibernate handoff <name> [--output path]
  devhibernate delete <name> [--force] [--delete-branch] [--keep-branch]
  devhibernate doctor
  devhibernate version

Lifecycle:
  start creates an isolated Git worktree and starts configured services.
  pause stops service processes while preserving code and task state.
  resume restarts services with fresh ports and restores local routes.
  handoff creates a safe Markdown context report without environment values.
  delete removes the worktree; dirty worktrees require --force.`)
}
