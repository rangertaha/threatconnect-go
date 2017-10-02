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

type Email struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`

	// Email specific properties
	To      string `json:"to,omitempty"`
	From    string `json:"from,omitempty"`
	Subject string `json:"subject,omitempty"`
	Header  string `json:"header,omitempty"`
	Body    string `json:"body,omitempty"`
}

type EmailResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Email       []Email `json:"email,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type EmailResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Email       Email `json:"email,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type EmailResource struct {
	TCResource
	email Email
}

func NewEmailResource(r TCResource) *EmailResource {
	r.Path("emails")
	return &EmailResource{TCResource: r}
}

func (r *EmailResource) Id(id int) *EmailResource {
	r.email.Id = id
	r.Path(id)
	return r
}

func (r *EmailResource) Retrieve() ([]Email, error) {
	if r.email.Id > 0 {
		grp, err := r.detail()
		grps := []Email{grp.Data.Email}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Email, err
}

func (r *EmailResource) detail() (*EmailResponseDetail, error) {
	grp := &EmailResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *EmailResource) list() (*EmailResponseList, error) {
	grp := &EmailResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *EmailResource) Create(g *Email) (Email, error) {
	grp := &EmailResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Email, ResourceError(grp.Message, res, err)
}

func (r *EmailResource) Update(g *Email) (Email, error) {
	grp := &EmailResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Email, ResourceError(grp.Message, res, err)
}
