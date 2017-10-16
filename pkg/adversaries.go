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

// Groups represent a collection of related behavior and/or intelligence.
package threatconnect

type Adversary struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`
}

type AdversaryResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Adversary   []Adversary `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AdversaryResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int       `json:"resultCount,omitempty"`
		Adversary   Adversary `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AdversaryResource struct {
	TCResource
	adversary Adversary
}

func NewAdversaryResource(r TCResource) *AdversaryResource {
	r.Path("adversaries")
	return &AdversaryResource{TCResource: r}
}

func (r *AdversaryResource) Id(id int) *AdversaryResource {
	r.adversary.Id = id
	r.Path(id)
	return r
}

func (r *AdversaryResource) Retrieve() ([]Adversary, error) {
	if r.adversary.Id > 0 {
		grp, err := r.detail()
		grps := []Adversary{grp.Data.Adversary}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Adversary, err
}

func (r *AdversaryResource) detail() (*AdversaryResponseDetail, error) {
	grp := &AdversaryResponseDetail{}
	_, err := r.Response(grp).Get()
	return grp, err
}

func (r *AdversaryResource) list() (*AdversaryResponseList, error) {
	grp := &AdversaryResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AdversaryResource) Create(g *Adversary) (Adversary, error) {
	grp := &AdversaryResponseDetail{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.Adversary, err
}

func (r *AdversaryResource) Update(g *Adversary) (Adversary, error) {
	grp := &AdversaryResponseDetail{}
	r.Response(grp)
	_, err := r.Put(g)
	return grp.Data.Adversary, err
}


func (r *AdversaryResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}
