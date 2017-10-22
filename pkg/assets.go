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

// Package threatconnect represents a collection of related behavior and/or intelligence.
package threatconnect

// Asset for adversaries
type Asset struct {
	ID      int    `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	WebLink string `json:"webLink,omitempty"`
}

type AssetResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Asset       []Asset `json:"bucketAsset,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type AssetResource struct {
	TCResource
	asset Asset
}

func NewAssetResourceResource(r TCResource) *AssetResource {
	r.Path("adversaryAssets")
	return &AssetResource{TCResource: r}
}

func (r *AssetResource) Retrieve() ([]Asset, error) {
	asset := &AssetResponseList{}
	res, err := r.Response(asset).Get()
	return asset.Data.Asset, ResourceError(asset.Message, res, err)
}

func (r *AssetResource) PhoneNumbers(id ...int) {

}

func (r *AssetResource) Url(id ...int) {

}

func (r *AssetResource) Handles(id ...int) {

}
