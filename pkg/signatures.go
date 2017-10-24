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

// The valid values for a Signature’s fileType field are:
//
// Snort
// Suricata
// YARA
// ClamAV
// OpenIOC
// CybOX™
// Bro
// Regex
type Signature struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`

	// Signature specific properties
	FileName string `json:"fileName,omitempty"`
	FileType string `json:"fileType,omitempty"`
	FileText string `json:"fileText,omitempty"`
}

type SignatureResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Signature   []Signature `json:"signature,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type SignatureResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int       `json:"resultCount,omitempty"`
		Signature   Signature `json:"signature,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type SignatureResource struct {
	TCResource
	signature Signature
}

func NewSignatureResource(r TCResource) *SignatureResource {
	r.Path("signatures")
	return &SignatureResource{TCResource: r}
}

func (r *SignatureResource) Id(id int) *SignatureResource {
	r.signature.Id = id
	r.Path(id)
	return r
}

func (r *SignatureResource) Retrieve() ([]Signature, error) {
	if r.signature.Id > 0 {
		grp, err := r.detail()
		grps := []Signature{grp.Data.Signature}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Signature, err
}

func (r *SignatureResource) detail() (*SignatureResponseDetail, error) {
	grp := &SignatureResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *SignatureResource) list() (*SignatureResponseList, error) {
	grp := &SignatureResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *SignatureResource) Create(g *Signature) (Signature, error) {
	grp := &SignatureResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Signature, ResourceError(grp.Message, res, err)
}

func (r *SignatureResource) Update(g *Signature) (Signature, error) {
	grp := &SignatureResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Signature, ResourceError(grp.Message, res, err)
}

func (r *SignatureResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}