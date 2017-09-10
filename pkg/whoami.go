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

// Shows your user information
package threatconnect

type User struct {
	UserName  string `json:"userName,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Pseudonym string `json:"pseudonym,omitempty"`
	Role      string `json:"role,omitempty"`
}

type WhoAmIResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int  `json:"resultCount,omitempty"`
		User        User `json:"user,omitempty"`
	} `json:"data,omitempty"`
}

type WhoAmIResource struct {
	*TCResource
}

func NewWhoAmI(tc *ThreatConnectClient) *WhoAmIResource {
	return &WhoAmIResource{
		&TCResource{
			TC:        tc,
			RBase:     tc.Config.Version,
			RResponse: WhoAmIResponseDetail{},
		},
	}
}

func (r *WhoAmIResource) WhoAmI() *WhoAmIResource {
	r.RResponse = new(WhoAmIResponseDetail)
	r.RPath = "whoami"
	return r
}
