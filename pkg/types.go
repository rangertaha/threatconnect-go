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

type TypesResource struct {
	TCResource
}

func NewTypesResource(r TCResource) *TypesResource {
	r.Path("types")
	return &TypesResource{TCResource: r}
}

func (r *TypesResource) AssociationType(name ...string) *AssociationTypeResource {
	if len(name) > 0 {
		return NewAssociationTypeResource(r.TCResource).Name(name[0])
	}
	return NewAssociationTypeResource(r.TCResource)
}
