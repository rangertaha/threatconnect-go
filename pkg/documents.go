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
func (r *DocumentResource) Attributes(id ...int) *AttributesResource {
	if len(id) > 0 {
		return NewAttributesResource(r.TCResource).Id(id[0])
	}
	return NewAttributesResource(r.TCResource)
}
