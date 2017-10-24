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


package threatconnect

//"encoding/json"

type Attribute struct {
	ID           int    `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	Value        string `json:"value,omitempty"`
	DateAdded    string `json:"dateAdded,omitempty"`
	Displayed    bool   `json:"displayed,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

type AttributesResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int         `json:"resultCount,omitempty"`
		Attributes  []Attribute `json:"attribute,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AttributeResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int       `json:"resultCount,omitempty"`
		Attributes  Attribute `json:"attribute,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AttributesResource struct {
	TCResource
	attribute Attribute
}

func NewAttributesResource(r TCResource) *AttributesResource {
	r.Path("attributes")
	return &AttributesResource{TCResource: r}
}

func (r *AttributesResource) Id(id int) *AttributesResource {
	r.attribute.ID = id
	r.Path(id)
	return r
}

func (r *AttributesResource) Retrieve() ([]Attribute, error) {
	if r.attribute.ID > 0 {
		grp, err := r.detail()
		grps := []Attribute{grp.Data.Attributes}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Attributes, err
}

func (r *AttributesResource) detail() (*AttributeResponseDetail, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) list() (*AttributesResponseList, error) {
	grp := &AttributesResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) Create(g *Attribute) (Attribute, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Post(g)
	return grp.Data.Attributes, ResourceError(grp.Message, res, err)
}

func (r *AttributesResource) Update(g *Attribute) (Attribute, error) {
	grp := &AttributeResponseDetail{}
	res, err := r.Response(grp).Put(g)
	return grp.Data.Attributes, ResourceError(grp.Message, res, err)
}

//
//
//func NewAttributesResource(r TCResource) *AttributesResource {
//	r.Path("attributes")
//	return &AttributesResource{TCResource: r}
//}
//
//
//
//func (r *AttributesResource) Retrieve() ([]Attribute, error) {
//	if r.attribute.Id > 0 {
//		grp, err := r.detail()
//		grps := []Attribute{grp.Data.Attribute}
//		return grps, err
//	}
//
//	grps, err := r.list()
//	return grps.Data.Attribute, err
//}
//
//func (r *AttributesResource) detail() (*AttributeResponseDetail, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Get()
//	return grp, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) list() (*AttributeResponseList, error) {
//	grp := &AttributeResponseList{}
//	res, err := r.Response(grp).Get()
//	return grp, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) Create(g *Attribute) (Attribute, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Post(g)
//	return grp.Data.Attribute, ResourceError(grp.Message, res, err)
//}
//
//func (r *AttributesResource) Update(g *Attribute) (Attribute, error) {
//	grp := &AttributeResponseDetail{}
//	res, err := r.Response(grp).Put(g)
//	return grp.Data.Attribute, ResourceError(grp.Message, res, err)
//}
