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

// Adversary Assets are accounts or web resources that Adversaries leverage in
// support of their operations.
package threatconnect

import (
	//"net/http"
	"encoding/json"
	//log "github.com/Sirupsen/logrus"
)

type AdversaryResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Groups      []Group `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
}

type AdversaryResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Groups      Group `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
}

type AdversaryAssetsResource struct {
	TCResource
}

func NewAdversaryAssetsResource(r TCResource) *AdversaryAssetsResource {
	r.Path("victimAssets")
	r.Response(new(json.RawMessage))
	return &AdversaryAssetsResource{r}
}

func (r *AdversaryAssetsResource) Type(gtype string) *AdversaryAssetsResource {
	r.Response(new(json.RawMessage))
	r.Path(gtype)
	return r
}

func (r *AdversaryAssetsResource) Id(id string) *AdversaryAssetsResource {
	r.Response(new(json.RawMessage))
	r.Path(id)
	return r
}

func (r *AdversaryAssetsResource) Handles(id ...string) *AdversaryAssetsResource {
	r.Path("handles")
	r.Response(new(json.RawMessage))
	if len(id[0]) == 1 {
		r.Path(id[0])
	}
	return r
}

func (r *AdversaryAssetsResource) PhoneNumbers(id ...string) *AdversaryAssetsResource {
	r.Path("phoneNumbers")
	r.Response(new(json.RawMessage))
	if len(id[0]) == 1 {
		r.Path(id[0])
	}
	return r
}

func (r *AdversaryAssetsResource) Urls(id ...string) *AdversaryAssetsResource {
	r.Path("urls")
	r.Response(new(json.RawMessage))
	if len(id[0]) == 1 {
		r.Path(id[0])
	}
	return r
}
