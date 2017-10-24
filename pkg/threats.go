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

type Threat struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	Owner     Owner  `json:"owner,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`
}

type ThreatResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int      `json:"resultCount,omitempty"`
		Threat      []Threat `json:"threat,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type ThreatResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int    `json:"resultCount,omitempty"`
		Threat      Threat `json:"threat,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type ThreatResource struct {
	TCResource
	threat Threat
}

func NewThreatResource(r TCResource) *ThreatResource {
	r.Path("threats")
	return &ThreatResource{TCResource: r}
}

func (r *ThreatResource) Id(id int) *ThreatResource {
	r.threat.Id = id
	r.Path(id)
	return r
}

func (r *ThreatResource) Retrieve() ([]Threat, error) {
	if r.threat.Id > 0 {
		grp, err := r.detail()
		grps := []Threat{grp.Data.Threat}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Threat, err
}

func (r *ThreatResource) detail() (*ThreatResponseDetail, error) {
	grp := &ThreatResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *ThreatResource) list() (*ThreatResponseList, error) {
	grp := &ThreatResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *ThreatResource) Create(g *Threat) (Threat, error) {
	grp := &ThreatResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Threat, ResourceError(grp.Message, res, err)
}

func (r *ThreatResource) Update(g *Threat) (Threat, error) {
	grp := &ThreatResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Threat, ResourceError(grp.Message, res, err)
}

func (r *ThreatResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}