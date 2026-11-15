package acme

import (
	"encoding/json/v2"
	"fmt"
)

type Problem struct {
	Type        string       `json:"type,omitempty"`
	Title       string       `json:"title,omitempty"`
	Status      int64        `json:"status,omitzero"`
	Detail      string       `json:"detail,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

type Subproblem struct {
	Type       string     `json:"type,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Identifier Identifier `json:"identifier,omitzero"`
}

func (p *Problem) Error() string {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("%#v", *p)
	}
	return string(b)
}
