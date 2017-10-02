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

import (
	"errors"
)

type Group struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`
}

type GroupResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Groups      []Group `json:"group,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type GroupResource struct {
	TCResource
}

func NewGroupResource(r TCResource) *GroupResource {
	r.Path("groups")
	return &GroupResource{TCResource: r}
}

func (r *GroupResource) Retrieve() ([]Group, error) {
	grps := &GroupResponseList{}
	r.Response(grps)
	_, err := r.TCResource.Get()
	if grps.Status == "Failure" {
		err = errors.New(grps.Message)
	}
	return grps.Data.Groups, err
}

func (r *GroupResource) Adversaries(id ...int) *AdversaryResource {
	if len(id) > 0 {
		return NewAdversaryResource(r.TCResource).Id(id[0])
	}
	return NewAdversaryResource(r.TCResource)
}

func (r *GroupResource) Incidents(id ...int) *IncidentResource {
	if len(id) > 0 {
		return NewIncidentResource(r.TCResource).Id(id[0])
	}
	return NewIncidentResource(r.TCResource)
}

func (r *GroupResource) Threats(id ...int) *ThreatResource {
	if len(id) > 0 {
		return NewThreatResource(r.TCResource).Id(id[0])
	}
	return NewThreatResource(r.TCResource)
}

func (r *GroupResource) Emails(id ...int) *EmailResource {
	if len(id) > 0 {
		return NewEmailResource(r.TCResource).Id(id[0])
	}
	return NewEmailResource(r.TCResource)
}

func (r *GroupResource) Campaigns(id ...int) *CampaignResource {
	if len(id) > 0 {
		return NewCampaignResource(r.TCResource).Id(id[0])
	}
	return NewCampaignResource(r.TCResource)
}

func (r *GroupResource) Signatures(id ...int) *SignatureResource {
	if len(id) > 0 {
		return NewSignatureResource(r.TCResource).Id(id[0])
	}
	return NewSignatureResource(r.TCResource)
}

func (r *GroupResource) Documents(id ...int) *DocumentResource {
	if len(id) > 0 {
		return NewDocumentResource(r.TCResource).Id(id[0])
	}
	return NewDocumentResource(r.TCResource)
}
