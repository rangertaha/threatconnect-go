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

// The valid values for an Incident’s status are:
//
// New
// Open
// Stalled
// Containment Achieved
// Restoration Achieved
// Incident Reported
// Closed
// Rejected
// Deleted
type Incident struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`
	Owner     Owner  `json:"owner,omitempty"`

	// Incident specific properties
	Status string `json:"status,omitempty"`
}

type IncidentResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int        `json:"resultCount,omitempty"`
		Incident    []Incident `json:"incident,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type IncidentResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int      `json:"resultCount,omitempty"`
		Incident    Incident `json:"incident,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type IncidentResource struct {
	TCResource
	incident Incident
}

func NewIncidentResource(r TCResource) *IncidentResource {
	r.Path("incidents")
	return &IncidentResource{TCResource: r}
}

func (r *IncidentResource) Id(id int) *IncidentResource {
	r.incident.Id = id
	r.Path(id)
	return r
}

func (r *IncidentResource) Retrieve() ([]Incident, error) {
	if r.incident.Id > 0 {
		grp, err := r.detail()
		grps := []Incident{grp.Data.Incident}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Incident, err
}

func (r *IncidentResource) detail() (*IncidentResponseDetail, error) {
	grp := &IncidentResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *IncidentResource) list() (*IncidentResponseList, error) {
	grp := &IncidentResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *IncidentResource) Create(g *Incident) (Incident, error) {
	grp := &IncidentResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Incident, ResourceError(grp.Message, res, err)
}

func (r *IncidentResource) Update(g *Incident) (Incident, error) {
	grp := &IncidentResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Incident, ResourceError(grp.Message, res, err)
}
