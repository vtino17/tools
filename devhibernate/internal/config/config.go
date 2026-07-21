package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const FileName = "devhibernate.json"

type Config struct {
	Version      int        `json:"version"`
	Project      string     `json:"project"`
	DefaultBase  string     `json:"defaultBase"`
	ProxyPort    int        `json:"proxyPort"`
	Setup        []string   `json:"setup,omitempty"`
	PassEnv      []string   `json:"passEnv,omitempty"`
	Services     []Service  `json:"services,omitempty"`
	Open         OpenConfig `json:"open,omitempty"`
	DeleteBranch bool       `json:"deleteBranchOnDelete"`
}

type Service struct {
	Name       string            `json:"name"`
	Command    string            `json:"command"`
	PortEnv    string            `json:"portEnv,omitempty"`
	Expose     bool              `json:"expose,omitempty"`
	Health     *HealthCheck      `json:"health,omitempty"`
	WorkingDir string            `json:"workingDir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
}

type HealthCheck struct {
	Type           string `json:"type"`
	Path           string `json:"path,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
}

type OpenConfig struct {
	Files []string `json:"files,omitempty"`
	URLs  []string `json:"urls,omitempty"`
}

func Default(project string) Config {
	return Config{
		Version:      1,
		Project:      project,
		DefaultBase:  "HEAD",
		ProxyPort:    7777,
		DeleteBranch: false,
		Services: []Service{
			{
				Name:    "web",
				Command: "npm run dev",
				PortEnv: "PORT",
				Expose:  true,
				Health:  &HealthCheck{Type: "http", Path: "/", TimeoutSeconds: 30},
			},
		},
	}
}

func Load(root string) (Config, error) {
	path := filepath.Join(root, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, fmt.Errorf("%s not found; run `devhibernate init`", FileName)
		}
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", FileName, err)
	}
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = 7777
	}
	if cfg.DefaultBase == "" {
		cfg.DefaultBase = "HEAD"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if strings.TrimSpace(c.Project) == "" {
		return fmt.Errorf("project is required")
	}
	seen := map[string]bool{}
	for i, svc := range c.Services {
		if strings.TrimSpace(svc.Name) == "" {
			return fmt.Errorf("services[%d].name is required", i)
		}
		if seen[svc.Name] {
			return fmt.Errorf("duplicate service name %q", svc.Name)
		}
		seen[svc.Name] = true
		if strings.TrimSpace(svc.Command) == "" {
			return fmt.Errorf("service %q command is required", svc.Name)
		}
		if svc.Health != nil {
			switch svc.Health.Type {
			case "", "none", "http", "tcp":
			default:
				return fmt.Errorf("service %q has unsupported health type %q", svc.Name, svc.Health.Type)
			}
		}
	}
	return nil
}

func WriteDefault(root, project string) error {
	cfg := Default(project)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(root, FileName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists", FileName)
		}
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
