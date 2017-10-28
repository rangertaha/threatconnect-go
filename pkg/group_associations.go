// The MIT License (MIT)

// Copyright (c) 2016 rangertaha

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
	r.Response(new(json.RawMessage))
	if len(gtype) == 1 {
		r.Path(gtype[0])
	}
	return r
}

func (r *AssociatedGroupTypesResource) AssociatedId(id ...string) *AssociatedGroupTypesResource {
	r.Response(new(json.RawMessage))
	if len(id) == 1 {
		r.Path(id[0])
	}
	return r
}

func (r *AssociatedIndicatorTypesResource) AssociatedType(itype ...string) *AssociatedIndicatorTypesResource {
	r.Response(new(json.RawMessage))
	if len(itype) == 1 {
		r.Path(itype[0])
	}
	return r
}

func (r *AssociatedIndicatorTypesResource) AssociatedId(id ...string) *AssociatedIndicatorTypesResource {
	r.Response(new(json.RawMessage))
	if len(id) == 1 {
		r.Path(id[0])
	}
	return r
}
