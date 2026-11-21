package cwe

import (
	"encoding/json"
	"fmt"
)

// Weakness defines a CWE weakness based on http://cwe.mitre.org/data/xsd/cwe_schema_v6.4.xsd
type Weakness struct {
	ID          string
	Name        string
	Description string
}

// SprintURL format the CWE URL
func (w *Weakness) SprintURL() string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", w.ID)
}

// SprintID format the CWE ID
func (w *Weakness) SprintID() string {
	id := "0000"
	if w != nil {
		id = w.ID
	}
	return fmt.Sprintf("%s-%s", Acronym, id)
}

// MarshalJSON print only id and URL
func (w *Weakness) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}{
		ID:  w.ID,
		URL: w.SprintURL(),
	})
}

// UnmarshalJSON reverses MarshalJSON and rehydrates the full weakness from
// the built-in CWE table. Without it, a round-tripped weakness (for example a
// gosec finding restored from a resume state) would keep its ID but lose the
// name and description that some report formatters render.
func (w *Weakness) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if full := Get(raw.ID); full != nil {
		*w = *full
		return nil
	}
	// Keep an unknown ID rather than dropping the association entirely.
	w.ID = raw.ID
	w.Name = ""
	w.Description = ""
	return nil
}
