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

// Everything in the ThreatConnect platform exists within an Owner.
// Think of the owner as the bucket or location in which data exists.
package threatconnect

import (
	"path"
)

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
}

type MetricsResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Metrics     OwnerMetric `json:"ownerMetric,omitempty"`
	} `json:"data,omitempty"`
}

type MembersResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int    `json:"resultCount,omitempty"`
		Users       []User `json:"user,omitempty"`
	} `json:"data,omitempty"`
}

type OwnerResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Owners      []Owner `json:"owner,omitempty"`
	} `json:"data,omitempty"`
}

type OwnerResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Owners      Owner `json:"owner,omitempty"`
	} `json:"data,omitempty"`
}

type OwnerResource struct {
	TCResource
	owner Owner
}

func NewOwners(tc *ThreatConnectClient) *OwnerResource {
	return &OwnerResource{
		"",
		TCResource{
			TC:   tc,
			base: path.Join(tc.Config.Version, "owners"),
		},
	}
}

func (r *OwnerResource) Owners(name ...string) *OwnerResource {
	if len(name) > 0 {
		r.owner.Name = name[0]
		r.Path(name[0])
	}
	return r
}

func (r *OwnerResource) Mine() *OwnerResource {
	return r.Owners("mine")
}

func (r *OwnerResource) Members() *OwnerResource {
	if r.owner.Name != "" {
		r.Path("members")
	} else {
		// Error: Members ist of owners.
	}
	return r
}

func (r *OwnerResource) Metrics() *OwnerResource {
	if r.owner.Name != "" {
		r.Path("metrics")
	}

	if r.id != "" {
		r.Response(new(MetricsResponseDetail))
	}
	r.Path("metrics")
	return r
}
