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


// AssociationTypes represent a collection of related behavior and/or intelligence.
package threatconnect

import (
//"errors"
)

type AssociationType struct {
	Name       string `json:"name,omitempty"`
	Custom     string `json:"custom,omitempty"`
	FileAction string `json:"fileAction,omitempty"`
	ApiBranch  string `json:"apiBranch,omitempty"`
}

type AssociationTypeResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount     int               `json:"resultCount,omitempty"`
		AssociationType []AssociationType `json:"associationType,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AssociationTypeResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount     int             `json:"resultCount,omitempty"`
		AssociationType AssociationType `json:"associationType,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AssociationTypeResource struct {
	associationTypeName string
	TCResource
}

func NewAssociationTypeResource(r TCResource) *AssociationTypeResource {
	r.Path("associationTypes")
	return &AssociationTypeResource{TCResource: r}
}

func (r *AssociationTypeResource) Name(name string) *AssociationTypeResource {
	r.associationTypeName = name
	r.Path(name)
	return r
}

func (r *AssociationTypeResource) Retrieve() ([]AssociationType, error) {
	if r.associationTypeName != "" {
		detail, err := r.detail()
		list := []AssociationType{detail.Data.AssociationType}
		return list, err
	}

	list, err := r.list()
	return list.Data.AssociationType, err
}

func (r *AssociationTypeResource) detail() (*AssociationTypeResponseDetail, error) {
	detail := &AssociationTypeResponseDetail{}
	res, err := r.Response(detail).Get()
	return detail, ResourceError(detail.Message, res, err)
}

func (r *AssociationTypeResource) list() (*AssociationTypeResponseList, error) {
	list := &AssociationTypeResponseList{}
	res, err := r.Response(list).Get()
	return list, ResourceError(list.Message, res, err)
}
