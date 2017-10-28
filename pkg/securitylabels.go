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

type SecurityLabel struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Color       string `json:"color,omitempty"`
	DateAdded   string `json:"dateAdded,omitempty"`
}

type SecurityLabelsResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount   int             `json:"resultCount,omitempty"`
		SecurityLabel []SecurityLabel `json:"securityLabel,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type SecurityLabelsResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount   int           `json:"resultCount,omitempty"`
		SecurityLabel SecurityLabel `json:"securityLabel,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type SecurityLabelsResource struct {
	TCResource
	securityLabel SecurityLabel
}

func NewSecurityLabelsResource(r TCResource) *SecurityLabelsResource {
	r.Path("securityLabels")
	return &SecurityLabelsResource{TCResource: r}
}

func (r *SecurityLabelsResource) Id(name ...string) *SecurityLabelsResource {
	if len(name) > 0 {
		r.securityLabel.Name = name[0]
		r.Path(name[0])
	}
	return r
}

func (r *SecurityLabelsResource) Retrieve() ([]SecurityLabel, error) {
	if r.securityLabel.Name != "" {
		resp, err := r.detail()
		res := []SecurityLabel{resp.Data.SecurityLabel}
		return res, err
	}

	resp, err := r.list()
	return resp.Data.SecurityLabel, err
}

func (r *SecurityLabelsResource) detail() (*SecurityLabelsResponseDetail, error) {
	resp := &SecurityLabelsResponseDetail{}
	res, err := r.Response(resp).Get()
	return resp, ResourceError(resp.Message, res, err)
}

func (r *SecurityLabelsResource) list() (*SecurityLabelsResponseList, error) {
	grp := &SecurityLabelsResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

// func (r *SecurityLabelsResource) Create() (SecurityLabelsResponseDetail, error) {
// 	resp := &SecurityLabelsResponseDetail{}
// 	res, err := r.Post(g)
// 	return resp, ResourceError(grp.Message, res, err)
// }

// func (r *SecurityLabelsResource) Update(g *SecurityLabel) (SecurityLabel, error) {
// 	grp := &SecurityLabelsResponseDetail{}
// 	res, err := r.Response(grp).Put(g)
// 	return grp.Data.SecurityLabel, ResourceError(grp.Message, res, err)
// }

func (r *SecurityLabelsResource) Groups() *AssociatedGroupResource {
	r.Path("groups")
	return NewAssociatedGroupResource(r.TCResource)
}
