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

// Documents represent a collection of related behavior and/or intelligence.
package threatconnect

type Document struct {
	Id        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`

	// Document specific properties
	FileName string `json:"fileName,omitempty"`
	Malware  bool   `json:"malware,omitempty"`
	Password string `json:"password,omitempty"`
}

type DocumentResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int        `json:"resultCount,omitempty"`
		Document    []Document `json:"document,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type DocumentResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int      `json:"resultCount,omitempty"`
		Document    Document `json:"document,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type DocumentResource struct {
	TCResource
	document Document
}

func NewDocumentResource(r TCResource) *DocumentResource {
	r.Path("documents")
	return &DocumentResource{TCResource: r}
}

func (r *DocumentResource) Id(id int) *DocumentResource {
	r.document.Id = id
	r.Path(id)
	return r
}

func (r *DocumentResource) Retrieve() ([]Document, error) {
	if r.document.Id > 0 {
		grp, err := r.detail()
		grps := []Document{grp.Data.Document}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Document, err
}

func (r *DocumentResource) detail() (*DocumentResponseDetail, error) {
	grp := &DocumentResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *DocumentResource) list() (*DocumentResponseList, error) {
	grp := &DocumentResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *DocumentResource) Create(g *Document) (Document, error) {
	grp := &DocumentResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Document, ResourceError(grp.Message, res, err)
}

func (r *DocumentResource) Update(g *Document) (Document, error) {
	grp := &DocumentResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Document, ResourceError(grp.Message, res, err)
}
