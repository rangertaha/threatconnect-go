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
	//"net/http"
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
	ResultCount int     `json:"resultCount,omitempty"`
	Groups      []Group `json:"group,omitempty"`
}

type GroupResponseDetail struct {
	ResultCount int     `json:"resultCount,omitempty"`
	Group      Group  `json:"group,omitempty"`
}

type GroupResource struct {
	TCResource
	group Group
}

func NewGroups(r TCResource) *GroupResource {
	r.Path("groups")
	return &GroupResource{TCResource:r}
}

func (r *GroupResource) Type(gtype string) *GroupResource {
	r.group.Type = gtype
	r.Path(gtype)
	return r
}

func (r *GroupResource) Id(id int) *GroupResource {
	r.group.Id = id
	r.Path(r.group.Type, r.group.Id)
	return r
}

func (r *GroupResource) Publish() *GroupResource {
	r.extendSegment().Path("publish")
	return r
}

func (r *GroupResource) Indicators() *AssociatedIndicatorTypesResource {
	r.extendSegment()
	return NewAssociatedIndicatorTypes(r.TCResource)
}

func (r *GroupResource) Groups() *AssociatedGroupTypesResource {
	r.extendSegment()
	return NewAssociatedGroupTypes(r.TCResource)
}

func (r *GroupResource) Attributes(id ...string) *AttributesResource {
	r.extendSegment()
	return NewAttributes(r.TCResource).Attributes(id...)
}

func (r *GroupResource) AssociatedgroupType(gtype ...string) *AssociatedGroupTypesResource {
	r.extendSegment()
	return NewAssociatedGroupTypes(r.TCResource).AssociatedType(gtype...)
}

func (r *GroupResource) Victims(id ...string) *VictimsResource {
	r.extendSegment()
	return NewVictims(r.TCResource).Victims(id...)
}

func (r *GroupResource) SecurityLabels(id ...string) *SecurityLabelsResource {
	r.extendSegment()
	return NewSecurityLabels(r.TCResource).SecurityLabels(id...)
}

func (r *GroupResource) VictimAssets() *VictimAssetsResource {
	r.extendSegment()
	return NewVictimAssetsResource(r.TCResource)
}

func (r *GroupResource) Tags(id ...string) *TagsResource {
	r.extendSegment()
	return NewTagsResource(r.TCResource).Tags(id...)
}

func (r *GroupResource) AdversaryAssets() *AdversaryAssetsResource {
	r.extendSegment()
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

func (r *GroupResource) extendSegment() *GroupResource {

	// Build the full path to this resource
	if r.group.Id > 0 {
		r.Path(r.group.Type, r.group.Id)
	} else {
		r.Path(r.group.Type)
	}
	return r
}

//func (r *GroupResource) Get() (*GroupResource, error) {
//	return r.TCResource.Get()
//}

//
//func (r *GroupResource) Retrieve() ([]Group, *http.Response, error) {
//	var groupResList GroupResponseList
//	var groupResDetail GroupResponseDetail
//
//	// Extend path segment of resource
//	resc := r.extendSegment()
//
//	if r.group.Id == 0 {
//		res, err := resc.TCResource.Get(&groupResList)
//		return groupResList.Groups, res, err
//	}
//
//	res, err := resc.TCResource.Get(&groupResDetail)
//	return []Group{groupResDetail.Group}, res, err
//}
//
//func (r *GroupResource) Create(g *Group) (Group, *http.Response, error) {
//	return nil, nil, nil
//}
//
//func (r *GroupResource) Update(g *Group) (Group, *http.Response, error) {
//	return nil, nil, nil
//}
//
//
