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

func (r *IncidentResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}