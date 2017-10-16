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
	//"encoding/json"
)

type Attribute struct {
	Id           int    `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	Value        string `json:"value,omitempty"`
	DateAdded    string `json:"dateAdded,omitempty"`
	Displayed    string `json:"displayed,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

type AttributesResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Attributes  []Attribute `json:"attribute,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AttributeResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Attributes  Attribute `json:"attribute,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AttributesResource struct {
	TCResource
	attribute Attribute 
}

func NewAttributesResource(r TCResource) *AttributesResource {
	r.Path("attributes")
	return &AttributesResource{TCResource: r}
}

func (r *AttributesResource) Id(id int) *AttributesResource {
	r.attribute.Id = id
	r.Path(id)
	return r
}


func (r *AttributesResource) Retrieve() ([]Attribute, error) {
	if r.attribute.Id > 0 {
		grp, err := r.detail()
		grps := []Attribute{grp.Data.Attributes}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Attributes, err
}

func (r *AttributesResource) detail() (*AttributeResponseDetail, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) list() (*AttributesResponseList, error) {
	grp := &AttributesResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) Create(g *Attribute) (Attribute, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Attributes, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) Update(g *Attribute) (Attribute, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Attributes, ResourceError(grp.Message, res, err)
}








//
//
//func NewAttributesResource(r TCResource) *AttributesResource {
//	r.Path("attributes")
//	return &AttributesResource{TCResource: r}
//}
//
//
//
//func (r *AttributesResource) Retrieve() ([]Attribute, error) {
//	if r.attribute.Id > 0 {
//		grp, err := r.detail()
//		grps := []Attribute{grp.Data.Attribute}
//		return grps, err
//	}
//
//	grps, err := r.list()
//	return grps.Data.Attribute, err
//}
//
//func (r *AttributesResource) detail() (*AttributeResponseDetail, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Get()
//	return grp, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) list() (*AttributeResponseList, error) {
//	grp := &AttributeResponseList{}
//	res, err := r.Response(grp).Get()
//	return grp, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) Create(g *Attribute) (Attribute, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Post(g)
//	return grp.Data.Attribute, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) Update(g *Attribute) (Attribute, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Put(g)
//	return grp.Data.Attribute, ResourceError(grp.Message, res, err)
//}
