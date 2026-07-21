package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Status string

const (
	StatusRunning Status = "running"
	StatusPaused  Status = "paused"
	StatusFailed  Status = "failed"
)

type ProjectState struct {
	Version        int                 `json:"version"`
	RepositoryRoot string              `json:"repositoryRoot"`
	Capsules       map[string]*Capsule `json:"capsules"`
}

type Capsule struct {
	Name      string           `json:"name"`
	Slug      string           `json:"slug"`
	Status    Status           `json:"status"`
	Branch    string           `json:"branch"`
	Base      string           `json:"base"`
	Worktree  string           `json:"worktree"`
	Note      string           `json:"note,omitempty"`
	Services  []ServiceRuntime `json:"services,omitempty"`
	LastCheck *CheckResult     `json:"lastCheck,omitempty"`
	LastError string           `json:"lastError,omitempty"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
	ResumedAt *time.Time       `json:"resumedAt,omitempty"`
	PausedAt  *time.Time       `json:"pausedAt,omitempty"`
}

type ServiceRuntime struct {
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	Port      int       `json:"port,omitempty"`
	PortEnv   string    `json:"portEnv,omitempty"`
	Host      string    `json:"host,omitempty"`
	URL       string    `json:"url,omitempty"`
	PID       int       `json:"pid,omitempty"`
	LogPath   string    `json:"logPath"`
	StartedAt time.Time `json:"startedAt"`
}

type CheckResult struct {
	Command    string    `json:"command"`
	ExitCode   int       `json:"exitCode"`
	LogPath    string    `json:"logPath"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func Slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = nonSlug.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if len(value) > 48 {
		value = strings.Trim(value[:48], "-")
	}
	return value
}

func ValidateCapsuleName(name string) (string, error) {
	slug := Slugify(name)
	if slug == "" {
		return "", fmt.Errorf("capsule name must contain a letter or number")
	}
	return slug, nil
}

func RepoID(root string) string {
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:12]
}

func (s Status) CanTransition(to Status) bool {
	switch s {
	case StatusRunning:
		return to == StatusPaused || to == StatusFailed
	case StatusPaused:
		return to == StatusRunning || to == StatusFailed
	case StatusFailed:
		return to == StatusRunning || to == StatusPaused
	default:
		return false
	}
}
