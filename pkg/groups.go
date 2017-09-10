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
	"net/http"
"strconv"
	"encoding/json"
	"path"
	"github.com/Sirupsen/logrus"
)

type Group struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
}

type GroupResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Groups      []Group `json:"group,omitempty"`
	} `json:"data,omitempty"`
}

type GroupResponse struct {
	ResultCount int     `json:"resultCount,omitempty"`
	Groups      []Group `json:"group,omitempty"`
	//Group      []Group `json:"group,omitempty"`
}

type GroupResource struct {
	TCResource
	Group
}

func NewGroups(r TCResource) *GroupResource {
	r.Path("groups")
	r.RResponse = new(GroupResponse)
	return &GroupResource{r, Group{}}
}

func (r *GroupResource) Type(gtype ...string) *GroupResource {
	r.Group.Type = gtype[0]
	return r
}

func (r *GroupResource) Id(id ...int) *GroupResource {
	r.Group.Id = id[0]
	return r
}

func (r *GroupResource) Publish() *GroupResource {
	r.Path("publish")
	return r
}

func (r *GroupResource) Indicators() *AssociatedIndicatorTypesResource {
	return NewAssociatedIndicatorTypes(r.TCResource)
}

func (r *GroupResource) Groups() *AssociatedGroupTypesResource {
	return NewAssociatedGroupTypes(r.TCResource)
}

func (r *GroupResource) Attributes(id ...string) *AttributesResource {
	return NewAttributes(r.TCResource).Attributes(id...)
}

func (r *GroupResource) AssociatedgroupType(gtype ...string) *AssociatedGroupTypesResource {
	return NewAssociatedGroupTypes(r.TCResource).AssociatedType(gtype...)
}

func (r *GroupResource) Victims(id ...string) *VictimsResource {
	return NewVictims(r.TCResource).Victims(id...)
}

func (r *GroupResource) SecurityLabels(id ...string) *SecurityLabelsResource {
	return NewSecurityLabels(r.TCResource).SecurityLabels(id...)
}

func (r *GroupResource) VictimAssets() *VictimAssetsResource {
	return NewVictimAssetsResource(r.TCResource)
}

func (r *GroupResource) Tags(id ...string) *TagsResource {
	return NewTagsResource(r.TCResource).Tags(id...)
}

func (r *GroupResource) AdversaryAssets() *AdversaryAssetsResource {
	return NewAdversaryAssetsResource(r.TCResource)
}

func (r *GroupResource) Adversaries(id ...int) *GroupResource {
	r.Type("adversaries")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Campaigns(id ...int) *GroupResource {
	r.Type("campaigns")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Documents(id ...int) *GroupResource {
	r.Type("documents")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Emails(id ...int) *GroupResource {
	r.Type("emails")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Incidents(id ...int) *GroupResource {
	r.Type("incidents")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Signatures(id ...int) *GroupResource {
	r.Type("signatures")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}

func (r *GroupResource) Threats(id ...int) *GroupResource {
	r.Type("threats")
	if len(id) == 1 {
		r.Id(id[0])
	}
	return r
}


func (r *GroupResource) Build() *GroupResource {
	logrus.Info(strconv.Itoa(r.Group.Id))
	// Build the full path to this resource
	if r.Group.Id > 0 {
		r.RPath = path.Join(r.RPath, r.Group.Type, strconv.Itoa(r.Group.Id))
	} else {
		r.RPath = path.Join(r.RPath, r.Group.Type)
	}
	return r
}

func (r *GroupResource) Get() (GroupResponse, *http.Response, error) {
	// Build and retrieve resource
	obj, res, err := r.Build().TCResource.Get()

	var groupResponse GroupResponse
	if err != nil {
		return groupResponse, res, err
	}

	err = json.Unmarshal(obj, &groupResponse)

	return groupResponse, res, err
}
