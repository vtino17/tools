package model

import "testing"

func TestSlugify(t *testing.T) {
	got := Slugify("  Fix Payment / Timeout  ")
	if got != "fix-payment-timeout" {
		t.Fatalf("Slugify() = %q", got)
	}
}

func TestValidateCapsuleNameRejectsSymbols(t *testing.T) {
	if _, err := ValidateCapsuleName("!!!"); err == nil {
		t.Fatal("expected invalid name error")
	}
}

func TestStatusTransitions(t *testing.T) {
	if !StatusRunning.CanTransition(StatusPaused) {
		t.Fatal("running should transition to paused")
	}
	if StatusPaused.CanTransition(StatusPaused) {
		t.Fatal("paused should not transition to paused")
	}
}
