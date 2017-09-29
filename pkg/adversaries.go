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
		ResultCount int     `json:"resultCount,omitempty"`
		Groups      []Group `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AdversaryResponse struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Groups      Group `json:"group,omitempty"`
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

func (r *AdversaryResource) Id(id ...int) *AdversaryResource {
	if len(id) > 0 {
		r.adversary.Id = id[0]
		r.Path(id)
	}
	return r
}

func (r *AdversaryResource) Publish() *AdversaryResource {
	r.Path("publish")
	return r
}

func (r *AdversaryResource) Retrieve() ([]Group, error) {
	if r.adversary.Id > 0 {
		grp := &AdversaryResponse{}
		r.Response(grp)
		res, err := r.Get()
		return []Group{grp.Data.Groups}, CheckResponse(res, err)
	}

	grps := &GroupResponseList{}
	r.Response(grps)
	res, err := r.TCResource.Get()
	return grps.Data.Groups, CheckResponse(res, err)
}

func (r *AdversaryResource) Create(g *Adversary) (Group, error) {
	grp := &AdversaryResponse{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.Groups, err
}

func (r *AdversaryResource) Update(g *Adversary) (Group, error) {
	return Group{}, nil
}

func (r *AdversaryResource) Delete() (Group, error) {
	return Group{}, nil
}

