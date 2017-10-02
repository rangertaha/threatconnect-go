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

type Campaign struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`

	// Campaign specific properties
	FirstSeen string `json:"firstSeen,omitempty"`
}

type CampaignResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int        `json:"resultCount,omitempty"`
		Campaign    []Campaign `json:"campaign,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type CampaignResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int      `json:"resultCount,omitempty"`
		Campaign    Campaign `json:"campaign,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type CampaignResource struct {
	TCResource
	campaign Campaign
}

func NewCampaignResource(r TCResource) *CampaignResource {
	r.Path("campaigns")
	return &CampaignResource{TCResource: r}
}

func (r *CampaignResource) Id(id int) *CampaignResource {
	r.campaign.Id = id
	r.Path(id)
	return r
}

func (r *CampaignResource) Retrieve() ([]Campaign, error) {
	if r.campaign.Id > 0 {
		grp, err := r.detail()
		grps := []Campaign{grp.Data.Campaign}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Campaign, err
}

func (r *CampaignResource) detail() (*CampaignResponseDetail, error) {
	grp := &CampaignResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *CampaignResource) list() (*CampaignResponseList, error) {
	grp := &CampaignResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *CampaignResource) Create(g *Campaign) (Campaign, error) {
	grp := &CampaignResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Campaign, ResourceError(grp.Message, res, err)
}

func (r *CampaignResource) Update(g *Campaign) (Campaign, error) {
	grp := &CampaignResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Campaign, ResourceError(grp.Message, res, err)
}
