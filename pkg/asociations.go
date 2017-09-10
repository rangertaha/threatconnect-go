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

// Retrieving Available Associations
// Available associations can be viewed with the Associations Resource
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

type AssociatedGroupTypesResource struct {
	TCResource
}

type AssociatedIndicatorTypesResource struct {
	TCResource
}

func NewAssociatedGroupTypes(r TCResource) *AssociatedGroupTypesResource {
	r.Path("groups")
	return &AssociatedGroupTypesResource{r}
}

func NewAssociatedIndicatorTypes(r TCResource) *AssociatedIndicatorTypesResource {
	r.Path("indicators")
	return &AssociatedIndicatorTypesResource{r}
}

func (r *AssociatedGroupTypesResource) AssociatedType(gtype ...string) *AssociatedGroupTypesResource {
	r.RResponse = new(json.RawMessage)
	if len(gtype) == 1 {
		r.Path(gtype[0])
	}
	return r
}

func (r *AssociatedGroupTypesResource) AssociatedId(id ...string) *AssociatedGroupTypesResource {
	r.RResponse = new(json.RawMessage)
	if len(id) == 1 {
		r.Path(id[0])
	}
	return r
}

func (r *AssociatedIndicatorTypesResource) AssociatedType(itype ...string) *AssociatedIndicatorTypesResource {
	r.RResponse = new(json.RawMessage)
	if len(itype) == 1 {
		r.Path(itype[0])
	}
	return r
}

func (r *AssociatedIndicatorTypesResource) AssociatedId(id ...string) *AssociatedIndicatorTypesResource {
	r.RResponse = new(json.RawMessage)
	if len(id) == 1 {
		r.Path(id[0])
	}
	return r
}
