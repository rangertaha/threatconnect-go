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

// type AssociatedGroup struct {
// 	Id        int    `json:"id,omitempty"`
// 	Name      string `json:"name,omitempty"`
// 	OwnerName string `json:"ownerName,omitempty"`
// 	DateAdded string `json:"dateAdded,omitempty"`
// 	WebLink   string `json:"webLink,omitempty"`
// 	EventDate string `json:"eventDate,omitempty"`
// }

type AssociatedResourceResponse struct {
	ApiCalls    int    `json:"apiCalls,omitempty"`
	Status      string `json:"status,omitempty"`
	ResultCount int    `json:"resultCount,omitempty"`
	Message     string `json:"message,omitempty"`
}

// type AssociatedAdversary struct {
// 	ID        int    `json:"id,omitempty"`
// 	Name      string `json:"name,omitempty"`
// 	Owner     Owner  `json:"owner,omitempty"`
// 	DateAdded string `json:"dateAdded,omitempty"`
// 	WebLink   string `json:"webLink,omitempty"`
// 	EventDate string `json:"eventDate,omitempty"`
// }

type AssociatedResource struct {
	TCResource
	ID int
}

func NewAssociatedResource(r TCResource) *AssociatedResource {
	return &AssociatedResource{TCResource: r}
}

func (r *AssociatedResource) Type(name string) *AssociatedResource {
	r.Path(name)
	return r
}

func (r *AssociatedResource) Id(id ...int) *AssociatedResource {
	if len(id) > 0 {
		r.Path(id[0])
		r.ID = id[0]
	}
	return r
}

type AssociatedGroupResource struct {
	AssociatedResource
}

func NewAssociatedGroupResource(r TCResource) *AssociatedGroupResource {
	return &AssociatedGroupResource{
		AssociatedResource{
			TCResource: r,
		},
	}
}

func (r *AssociatedGroupResource) Retrieve() ([]Group, error) {
	group := &GroupResponseList{}
	r.Response(group)
	res, err := r.TCResource.Get()
	return group.Data.Groups, ResourceError(group.Message, res, err)
}

func (r *AssociatedGroupResource) Adversaries(id ...int) *AssociatedAdversaryResource {
	r.Type("adversaries").Id(id...)
	return &AssociatedAdversaryResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Campaigns(id ...int) *AssociatedCampaignResource {
	r.Type("campaigns").Id(id...)
	return &AssociatedCampaignResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Documents(id ...int) *AssociatedDocumentResource {
	r.Type("documents").Id(id...)
	return &AssociatedDocumentResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Emails(id ...int) *AssociatedEmailResource {
	r.Type("emails").Id(id...)
	return &AssociatedEmailResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Incidents(id ...int) *AssociatedIncidentsResource {
	r.Type("incidents").Id(id...)
	return &AssociatedIncidentsResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Signatures(id ...int) *AssociatedSignaturesResource {
	r.Type("signatures").Id(id...)
	return &AssociatedSignaturesResource{r.AssociatedResource}
}

func (r *AssociatedGroupResource) Threats(id ...int) *AssociatedThreatsResource {
	r.Type("threats").Id(id...)
	return &AssociatedThreatsResource{r.AssociatedResource}
}

type AssociatedIndicatorResource struct {
	AssociatedResource
}

func NewAssociatedIndicatorResource(r TCResource) *AssociatedIndicatorResource {
	return &AssociatedIndicatorResource{
		AssociatedResource{
			TCResource: r,
		},
	}
}

func (r *AssociatedIndicatorResource) Retrieve() ([]Indicator, error) {
	indicator := &IndicatorResponseList{}
	r.Response(indicator)
	res, err := r.TCResource.Get()
	return indicator.Data.Indicators, ResourceError(indicator.Message, res, err)
}

func (r *AssociatedIndicatorResource) Adversaries(id ...int) *AssociatedAdversaryResource {
	r.Type("adversaries").Id(id...)
	return &AssociatedAdversaryResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Campaigns(id ...int) *AssociatedCampaignResource {
	r.Type("campaigns").Id(id...)
	return &AssociatedCampaignResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Documents(id ...int) *AssociatedDocumentResource {
	r.Type("documents").Id(id...)
	return &AssociatedDocumentResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Emails(id ...int) *AssociatedEmailResource {
	r.Type("emails").Id(id...)
	return &AssociatedEmailResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Incidents(id ...int) *AssociatedIncidentsResource {
	r.Type("incidents").Id(id...)
	return &AssociatedIncidentsResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Signatures(id ...int) *AssociatedSignaturesResource {
	r.Type("signatures").Id(id...)
	return &AssociatedSignaturesResource{r.AssociatedResource}
}

func (r *AssociatedIndicatorResource) Threats(id ...int) *AssociatedThreatsResource {
	r.Type("threats").Id(id...)
	return &AssociatedThreatsResource{r.AssociatedResource}
}

type AssociatedAdversaryResource struct {
	AssociatedResource
}

func (r *AssociatedAdversaryResource) Retrieve() ([]Adversary, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Adversary{grp.Data.Adversary}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Adversary, err
}

func (r *AssociatedAdversaryResource) detail() (*AdversaryResponseDetail, error) {
	grp := &AdversaryResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedAdversaryResource) list() (*AdversaryResponseList, error) {
	grp := &AdversaryResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedCampaignResource struct {
	AssociatedResource
}

func (r *AssociatedCampaignResource) Retrieve() ([]Campaign, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Campaign{grp.Data.Campaign}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Campaign, err
}

func (r *AssociatedCampaignResource) detail() (*CampaignResponseDetail, error) {
	grp := &CampaignResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedCampaignResource) list() (*CampaignResponseList, error) {
	grp := &CampaignResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedDocumentResource struct {
	AssociatedResource
}

func (r *AssociatedDocumentResource) Retrieve() ([]Document, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Document{grp.Data.Document}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Document, err
}

func (r *AssociatedDocumentResource) detail() (*DocumentResponseDetail, error) {
	grp := &DocumentResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedDocumentResource) list() (*DocumentResponseList, error) {
	grp := &DocumentResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedEmailResource struct {
	AssociatedResource
}

func (r *AssociatedEmailResource) Retrieve() ([]Email, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Email{grp.Data.Email}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Email, err
}

func (r *AssociatedEmailResource) detail() (*EmailResponseDetail, error) {
	grp := &EmailResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedEmailResource) list() (*EmailResponseList, error) {
	grp := &EmailResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedIncidentsResource struct {
	AssociatedResource
}

func (r *AssociatedIncidentsResource) Retrieve() ([]Incident, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Incident{grp.Data.Incident}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Incident, err
}

func (r *AssociatedIncidentsResource) detail() (*IncidentResponseDetail, error) {
	grp := &IncidentResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedIncidentsResource) list() (*IncidentResponseList, error) {
	grp := &IncidentResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedSignaturesResource struct {
	AssociatedResource
}

func (r *AssociatedSignaturesResource) Retrieve() ([]Signature, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Signature{grp.Data.Signature}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Signature, err
}

func (r *AssociatedSignaturesResource) detail() (*SignatureResponseDetail, error) {
	grp := &SignatureResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedSignaturesResource) list() (*SignatureResponseList, error) {
	grp := &SignatureResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

type AssociatedThreatsResource struct {
	AssociatedResource
}

func (r *AssociatedThreatsResource) Retrieve() ([]Threat, error) {
	if r.ID > 0 {
		grp, err := r.detail()
		grps := []Threat{grp.Data.Threat}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Threat, err
}

func (r *AssociatedThreatsResource) detail() (*ThreatResponseDetail, error) {
	grp := &ThreatResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AssociatedThreatsResource) list() (*ThreatResponseList, error) {
	grp := &ThreatResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}
