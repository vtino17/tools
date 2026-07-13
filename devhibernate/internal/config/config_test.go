package config

import "testing"

func TestValidateRejectsDuplicateServices(t *testing.T) {
	cfg := Config{
		Version: 1,
		Project: "demo",
		Services: []Service{
			{Name: "web", Command: "one"},
			{Name: "web", Command: "two"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate service error")
	}
}

func TestValidateRejectsUnknownHealthType(t *testing.T) {
	cfg := Config{
		Version:  1,
		Project:  "demo",
		Services: []Service{{Name: "web", Command: "run", Health: &HealthCheck{Type: "magic"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsupported health type error")
	}
}
