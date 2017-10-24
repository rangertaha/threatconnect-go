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

// Package threatconnect represents a collection of related behavior and/or intelligence.
package threatconnect

// The Adversary Group represents a malicious actor or group of actors.
type Adversary struct {
	ID        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	WebLink   string `json:"webLink,omitempty"`
	EventDate string `json:"eventDate,omitempty"`
}

type AdversaryResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Adversary   []Adversary `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AdversaryResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int       `json:"resultCount,omitempty"`
		Adversary   Adversary `json:"adversary,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AdversaryResource struct {
	TCResource
	adversary Adversary
}

func NewAdversaryResource(r TCResource) *AdversaryResource {
	r.Path("adversaries")
	return &AdversaryResource{TCResource: r}
}

func (r *AdversaryResource) Id(id int) *AdversaryResource {
	r.adversary.ID = id
	r.Path(id)
	return r
}

func (r *AdversaryResource) Retrieve() ([]Adversary, error) {
	if r.adversary.ID > 0 {
		grp, err := r.detail()
		grps := []Adversary{grp.Data.Adversary}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Adversary, err
}

func (r *AdversaryResource) detail() (*AdversaryResponseDetail, error) {
	grp := &AdversaryResponseDetail{}
	_, err := r.Response(grp).Get()
	return grp, err
}

func (r *AdversaryResource) list() (*AdversaryResponseList, error) {
	grp := &AdversaryResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AdversaryResource) Create(g *Adversary) (Adversary, error) {
	grp := &AdversaryResponseDetail{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.Adversary, err
}

func (r *AdversaryResource) Update(g *Adversary) (Adversary, error) {
	grp := &AdversaryResponseDetail{}
	r.Response(grp)
	_, err := r.Put(g)
	return grp.Data.Adversary, err
}

func (r *AdversaryResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}

func (r *AdversaryResource) Assets() *AssetResource {
	return NewAssetResourceResource(r.TCResource)
}
