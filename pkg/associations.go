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

// Groups represent a collection of related behavior and/or intelligence.
package threatconnect

// type AssociatedGroup struct {
// 	Id        int    `json:"id,omitempty"`
// 	Name      string `json:"name,omitempty"`
// 	OwnerName string `json:"ownerName,omitempty"`
// 	DateAdded string `json:"dateAdded,omitempty"`
// 	WebLink   string `json:"webLink,omitempty"`
// 	EventDate string `json:"eventDate,omitempty"`
// }

type AssociatedGroupResponse struct {
	ApiCalls    int    `json:"apiCalls,omitempty"`
	Status      string `json:"status,omitempty"`
	ResultCount int    `json:"resultCount,omitempty"`
	Message     string `json:"message,omitempty"`
}

type AssociatedGroupResource struct {
	TCResource
}

func NewAssociatedGroupResource(r TCResource) *AssociatedGroupResource {
	r.Path("groups")
	return &AssociatedGroupResource{TCResource: r}
}

func (r *AssociatedGroupResource) Retrieve() ([]Group, error) {
	group := &GroupResponseList{}
	r.Response(group)
	res, err := r.TCResource.Get()
	return group.Data.Groups, ResourceError(group.Message, res, err)
}

func (r *AssociatedGroupResource) Create() (*AssociatedGroupResponse, error) {
	resp := &AssociatedGroupResponse{}
	res, err := r.Response(resp).Method("POST").Request()
	return resp, ResourceError(resp.Message, res, err)
}

func (r *AssociatedGroupResource) Type(name string) *AssociatedGroupResource {
	r.Path(name)
	return r
}

func (r *AssociatedGroupResource) Id(id int) *AssociatedGroupResource {
	r.Path(id)
	return r
}

// func (r *AssociatedGroupResource) Adversaries(id ...int) *AssociatedAdversaryResource {
// 	return NewAssociatedAdversaryResource(r).Id(id...)
// }

func (r *AssociatedGroupResource) Incidents(id ...int) *AssociatedGroupResource {
	r.Type("incidents")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

func (r *AssociatedGroupResource) Threats(id ...int) *AssociatedGroupResource {
	r.Type("threats")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

func (r *AssociatedGroupResource) Emails(id ...int) *AssociatedGroupResource {
	r.Type("emails")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

func (r *AssociatedGroupResource) Campaigns(id ...int) *AssociatedGroupResource {
	r.Type("campaigns")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

func (r *AssociatedGroupResource) Signatures(id ...int) *AssociatedGroupResource {
	r.Type("signatures")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

func (r *AssociatedGroupResource) Documents(id ...int) *AssociatedGroupResource {
	r.Type("documents")
	if len(id) > 0 {
		return r.Id(id[0])
	}
	return r
}

// type AssociatedAdversaryResource struct {
// 	AssociatedGroupResource
// }

// func NewAssociatedAdversaryResource(r AssociatedGroupResource) *AssociatedAdversaryResource {
// 	r.Type("adversaries")
// 	return &AssociatedAdversaryResource{r}
// }
// func (r *AssociatedAdversaryResource) Id(id ...int) *AssociatedAdversaryResource {
// 	if len(id) > 0 {
// 		r.Path(id[0])
// 	}
// 	return r
// }

// func (r *AssociatedAdversaryResource) Retrieve() ([]Adversary, error) {
// 	if len(id) > 0 {
// 		r.Path(id[0])
// 	}
// 	return r
// }

// func (r *AttributesResource) Retrieve() ([]Attribute, error) {
// 	if r.attribute.ID > 0 {
// 		grp, err := r.detail()
// 		grps := []Attribute{grp.Data.Attributes}
// 		return grps, err
// 	}

// 	grps, err := r.list()
// 	return grps.Data.Attributes, err
// }

// func (r *AttributesResource) detail() (*AttributeResponseDetail, error) {
// 	grp := &AttributeResponseDetail{}
// 	res, err := r.Response(grp).Get()
// 	return grp, ResourceError(grp.Message, res, err)
// }

// func (r *AttributesResource) list() (*AttributesResponseList, error) {
// 	grp := &AttributesResponseList{}
// 	res, err := r.Response(grp).Get()
// 	return grp, ResourceError(grp.Message, res, err)
// }
