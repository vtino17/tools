package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vtino17/devhibernate/internal/model"
)

const stateDir = ".devhibernate"

func StatePath(root string) string {
	return filepath.Join(root, stateDir, "state.json")
}

func LogsDir(root string) string {
	return filepath.Join(root, stateDir, "logs")
}

func Load(root string) (*model.ProjectState, error) {
	path := StatePath(root)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &model.ProjectState{Version: 1, RepositoryRoot: root, Capsules: map[string]*model.Capsule{}}, nil
		}
		return nil, err
	}
	var state model.ProjectState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if state.Capsules == nil {
		state.Capsules = map[string]*model.Capsule{}
	}
	return &state, nil
}

func Save(root string, state *model.ProjectState) error {
	dir := filepath.Dir(StatePath(root))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, "state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, StatePath(root))
}
