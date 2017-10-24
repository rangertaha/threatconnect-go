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


// Everything in the ThreatConnect platform exists within an Owner.
// Think of the owner as the bucket or location in which data exists.
package threatconnect

import "path"

type Owner struct {
	Id   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type OwnerMetric struct {
	MetricDate                   string  `json:"metricDate,omitempty"`
	TotalIndicator               int     `json:"totalIndicator,omitempty"`
	TotalHost                    int     `json:"totalHost,omitempty"`
	TotalAddress                 int     `json:"totalAddress,omitempty"`
	TotalEmailAddress            int     `json:"totalEmailAddress,omitempty"`
	TotalFile                    int     `json:"totalFile,omitempty"`
	TotalUrl                     int     `json:"totalUrl,omitempty"`
	TotalGroup                   int     `json:"totalGroup,omitempty"`
	TotalThreat                  int     `json:"totalThreat,omitempty"`
	TotalIncident                int     `json:"totalIncident,omitempty"`
	TotalEmail                   int     `json:"totalEmail,omitempty"`
	TotalCampaign                int     `json:"totalCampaign,omitempty"`
	TotalAdversary               int     `json:"totalAdversary,omitempty"`
	TotalSignature               int     `json:"totalSignature,omitempty"`
	TotalTask                    int     `json:"totalTask,omitempty"`
	TotalDocument                int     `json:"totalDocument,omitempty"`
	TotalTag                     int     `json:"totalTag,omitempty"`
	TotalTrack                   int     `json:"totalTrack,omitempty"`
	TotalResult                  int     `json:"totalResult,omitempty"`
	TotalIndicatorAttribute      int     `json:"totalIndicatorAttribute,omitempty"`
	TotalGroupAttribute          int     `json:"totalGroupAttribute,omitempty"`
	AverageIndicatorRating       float32 `json:"averageIndicatorRating,omitempty"`
	AverageIndicatorConfidence   float32 `json:"averageIndicatorConfidence,omitempty"`
	TotalEnrichedIndicator       int     `json:"totalEnrichedIndicator,omitempty"`
	TotalGroupIndicator          int     `json:"totalGroupIndicator,omitempty"`
	TotalObservationDaily        int     `json:"totalObservationDaily,omitempty"`
	TotalObservationIndicator    int     `json:"totalObservationIndicator,omitempty"`
	TotalObservationAddress      int     `json:"totalObservationAddress,omitempty"`
	TotalObservationEmailAddress int     `json:"totalObservationEmailAddress,omitempty"`
	TotalObservationFile         int     `json:"totalObservationFile,omitempty"`
	TotalObservationHost         int     `json:"totalObservationHost,omitempty"`
	TotalObservationUrl          int     `json:"totalObservationUrl,omitempty"`
	TotalFalsePositiveDaily      int     `json:"totalFalsePositiveDaily,omitempty"`
	TotalFalsePositive           int     `json:"totalFalsePositive,omitempty"`
}

type MetricsResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int           `json:"resultCount,omitempty"`
		Metrics     []OwnerMetric `json:"ownerMetric,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type MetricsResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Metrics     OwnerMetric `json:"ownerMetric,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type MembersResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int    `json:"resultCount,omitempty"`
		User        []User `json:"user,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type OwnerResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Owner       []Owner `json:"owner,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type OwnerResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Owner       Owner `json:"owner,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type OwnerResource struct {
	TCResource
	owner Owner
}

func NewOwnerResource(t *ThreatConnectClient) *OwnerResource {
	return &OwnerResource{
		TCResource: TCResource{
			TC:   t,
			base: path.Join(t.Config.Version, "owners"),
		},
	}
}

func (r *OwnerResource) Id(id ...int) *OwnerResource {
	if len(id) > 0 {
		r.owner.Id = id[0]
		r.Path(id[0])
	}
	return r
}

func (r *OwnerResource) Mine() *OwnerResource {
	r.owner.Id = 1
	r.Path("mine")
	return r
}

func (r *OwnerResource) Retrieve() ([]Owner, error) {
	if r.owner.Id > 0 {
		grp, err := r.detail()
		grps := []Owner{grp.Data.Owner}
		return grps, err
	}
	grps, err := r.list()
	return grps.Data.Owner, err
}

func (r *OwnerResource) detail() (*OwnerResponseDetail, error) {
	grp := &OwnerResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *OwnerResource) list() (*OwnerResponseList, error) {
	grp := &OwnerResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}
