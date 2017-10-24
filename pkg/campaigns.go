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

func (r *CampaignResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}
