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
