// Copyright © 2017 rangertaha <rangertaha@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package threatconnect

import (
	"encoding/json"
	//"path"
)

type SecurityLabel struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Color       string `json:"color,omitempty"`
	DateAdded   string `json:"dateAdded,omitempty"`
}

type SecurityLabelResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount    int             `json:"resultCount,omitempty"`
		SecurityLabels []SecurityLabel `json:"securityLabel,omitempty"`
	} `json:"data,omitempty"`
}

type SecurityLabelsResource struct {
	TCResource
}

func NewSecurityLabels(r TCResource) *SecurityLabelsResource {
	r.Path("securityLabels")
	return &SecurityLabelsResource{r}
}

func (r *SecurityLabelsResource) SecurityLabels(id ...string) *SecurityLabelsResource {
	r.Response(new(json.RawMessage))
	if len(id) == 1 {
		r.Path(id[0])
	}
	return r
}
