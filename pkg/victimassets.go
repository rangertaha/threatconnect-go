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
)

//type Attribute struct {
//	Id   int    `json:"id,omitempty"`
//	Name string `json:"name,omitempty"`
//	Type string `json:"type,omitempty"`
//	Value string `json:"value,omitempty"`
//	DateAdded string `json:"dateAdded,omitempty"`
//	Displayed string `json:"displayed,omitempty"`
//	LastModified string `json:"lastModified,omitempty"`
//}
//
//type AttributesResponseList struct {
//	Status string `json:"status,omitempty"`
//	Data   struct {
//		ResultCount int     `json:"resultCount,omitempty"`
//		Attributes      []Attribute `json:"attribute,omitempty"`
//	} `json:"data,omitempty"`
//}

type VictimAssetsResource struct {
	TCResource
}

func NewVictimAssetsResource(r TCResource) *VictimAssetsResource {
	r.Path("victimAssets")
	return &VictimAssetsResource{r}
}

func (r *VictimAssetsResource) Type(gtype ...string) *VictimAssetsResource {
	r.RResponse = new(json.RawMessage)
	r.Path(gtype[0])
	return r
}

func (r *VictimAssetsResource) Id(id ...string) *VictimAssetsResource {
	r.RResponse = new(json.RawMessage)
	r.Path(id[0])
	return r
}
