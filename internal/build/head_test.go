package build

import (
	"os"
	"testing"
)

// The head is the panel's: scripts/panel-vectors.ts copies it to testdata/panel.
func TestHead(t *testing.T) {
	panel, err := os.ReadFile("../../testdata/panel/openweir-head.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if Head != string(panel) {
		t.Errorf("Head differs from the panel's template head; update internal/build/head.go from testdata/panel/openweir-head.yaml (bun scripts/panel-vectors.ts ../api-edge)")
	}
}
