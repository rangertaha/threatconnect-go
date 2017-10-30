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

// Indicators represent a collection of related behavior and/or intelligence.
package threatconnect

import (
	"errors"
)

type Indicator struct {
	ID                     int    `json:"id,omitempty"`
	OwnerName              string `json:"ownerName,omitempty"`
	Type                   string `json:"type,omitempty"`
	DateAdded              string `json:"dateAdded,omitempty"`
	LastModified           string `json:"lastModified,omitempty"`
	Rating                 int    `json:"rating,omitempty"`
	Confidence             int    `json:"confidence,omitempty"`
	ThreatAssessRating     int    `json:"threatAssessRating,omitempty"`
	ThreatAssessConfidence int    `json:"threatAssessConfidence,omitempty"`
	WebLink                string `json:"webLink,omitempty"`
	Summary                string `json:"summary,omitempty"`
}

type IndicatorResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Indicators  []Indicator `json:"indicator,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type IndicatorResource struct {
	TCResource
}

func NewIndicatorResource(r TCResource) *IndicatorResource {
	r.Path("indicators")
	return &IndicatorResource{TCResource: r}
}

func (r *IndicatorResource) Retrieve() ([]Indicator, error) {
	grps := &IndicatorResponseList{}
	r.Response(grps)
	_, err := r.TCResource.Get()
	if grps.Status == "Failure" {
		err = errors.New(grps.Message)
	}
	return grps.Data.Indicators, err
}

func (r *IndicatorResource) Adversaries(id ...int) *AdversaryResource {
	if len(id) > 0 {
		return NewAdversaryResource(r.TCResource).Id(id[0])
	}
	return NewAdversaryResource(r.TCResource)
}

func (r *IndicatorResource) Incidents(id ...int) *IncidentResource {
	if len(id) > 0 {
		return NewIncidentResource(r.TCResource).Id(id[0])
	}
	return NewIncidentResource(r.TCResource)
}

func (r *IndicatorResource) Threats(id ...int) *ThreatResource {
	if len(id) > 0 {
		return NewThreatResource(r.TCResource).Id(id[0])
	}
	return NewThreatResource(r.TCResource)
}

func (r *IndicatorResource) Emails(id ...int) *EmailResource {
	if len(id) > 0 {
		return NewEmailResource(r.TCResource).Id(id[0])
	}
	return NewEmailResource(r.TCResource)
}

func (r *IndicatorResource) Campaigns(id ...int) *CampaignResource {
	if len(id) > 0 {
		return NewCampaignResource(r.TCResource).Id(id[0])
	}
	return NewCampaignResource(r.TCResource)
}

func (r *IndicatorResource) Signatures(id ...int) *SignatureResource {
	if len(id) > 0 {
		return NewSignatureResource(r.TCResource).Id(id[0])
	}
	return NewSignatureResource(r.TCResource)
}

func (r *IndicatorResource) Documents(id ...int) *DocumentResource {
	if len(id) > 0 {
		return NewDocumentResource(r.TCResource).Id(id[0])
	}
	return NewDocumentResource(r.TCResource)
}
