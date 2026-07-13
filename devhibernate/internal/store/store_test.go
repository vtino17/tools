package store

import (
	"testing"

	"github.com/vtino17/devhibernate/internal/model"
)

func TestSaveAndLoad(t *testing.T) {
	root := t.TempDir()
	state := &model.ProjectState{
		Version:        1,
		RepositoryRoot: root,
		Capsules: map[string]*model.Capsule{
			"demo": {Name: "Demo", Slug: "demo", Status: model.StatusPaused},
		},
	}
	if err := Save(root, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Capsules["demo"].Name != "Demo" {
		t.Fatalf("unexpected state: %#v", loaded)
	}
}
