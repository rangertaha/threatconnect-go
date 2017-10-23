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
<<<<<<< HEAD

	PhoneNumber string `json:"phoneNumber,omitempty"`
	Handle      string `json:"handle,omitempty"`
	Url         string `json:"url,omitempty"`
=======
>>>>>>> 7f36e8cae6e0e011996ec5a83466db3dd59f9ba7
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

<<<<<<< HEAD
func (r *AssetResource) PhoneNumbers(id ...int) *PhoneNumberResource {
	if len(id) > 0 {
		return NewPhoneNumberResource(r.TCResource).Id(id[0])
	}
	return NewPhoneNumberResource(r.TCResource)
}

func (r *AssetResource) Urls(id ...int) *UrlResource {
	if len(id) > 0 {
		return NewUrlResource(r.TCResource).Id(id[0])
	}
	return NewUrlResource(r.TCResource)
}

func (r *AssetResource) Handles(id ...int) *HandleResource {
	if len(id) > 0 {
		return NewHandleResource(r.TCResource).Id(id[0])
	}
	return NewHandleResource(r.TCResource)
}

type PhoneNumberResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		PhoneNumber []Asset `json:"adversaryPhoneNumber,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type PhoneNumberResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		PhoneNumber Asset `json:"adversaryPhoneNumber,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type PhoneNumberResource struct {
	TCResource
	asset Asset
}

func NewPhoneNumberResource(r TCResource) *PhoneNumberResource {
	r.Path("phoneNumbers")
	return &PhoneNumberResource{TCResource: r}
}

func (r *PhoneNumberResource) Id(id int) *PhoneNumberResource {
	r.asset.ID = id
	r.Path(id)
	return r
}

func (r *PhoneNumberResource) Retrieve() ([]Asset, error) {
	if r.asset.ID > 0 {
		grp, err := r.detail()
		grps := []Asset{grp.Data.PhoneNumber}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.PhoneNumber, err
}

func (r *PhoneNumberResource) detail() (*PhoneNumberResponseDetail, error) {
	grp := &PhoneNumberResponseDetail{}
	_, err := r.Response(grp).Get()
	return grp, err
}

func (r *PhoneNumberResource) list() (*PhoneNumberResponseList, error) {
	grp := &PhoneNumberResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *PhoneNumberResource) Create(g *Asset) (Asset, error) {
	grp := &PhoneNumberResponseDetail{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.PhoneNumber, err
}

func (r *PhoneNumberResource) Update(g *Asset) (Asset, error) {
	grp := &PhoneNumberResponseDetail{}
	r.Response(grp)
	_, err := r.Put(g)
	return grp.Data.PhoneNumber, err
}

type UrlResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Url         []Asset `json:"adversaryUrl,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type UrlResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Url         Asset `json:"adversaryUrl,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type UrlResource struct {
	TCResource
	asset Asset
}

func NewUrlResource(r TCResource) *UrlResource {
	r.Path("urls")
	return &UrlResource{TCResource: r}
}

func (r *UrlResource) Id(id int) *UrlResource {
	r.asset.ID = id
	r.Path(id)
	return r
}

func (r *UrlResource) Retrieve() ([]Asset, error) {
	if r.asset.ID > 0 {
		grp, err := r.detail()
		grps := []Asset{grp.Data.Url}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Url, err
}

func (r *UrlResource) detail() (*UrlResponseDetail, error) {
	grp := &UrlResponseDetail{}
	_, err := r.Response(grp).Get()
	return grp, err
}

func (r *UrlResource) list() (*UrlResponseList, error) {
	grp := &UrlResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *UrlResource) Create(g *Asset) (Asset, error) {
	grp := &UrlResponseDetail{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.Url, err
}

func (r *UrlResource) Update(g *Asset) (Asset, error) {
	grp := &UrlResponseDetail{}
	r.Response(grp)
	_, err := r.Put(g)
	return grp.Data.Url, err
}

type HandleResponseList struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int     `json:"resultCount,omitempty"`
		Handle      []Asset `json:"adversaryHandle,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type HandleResponseDetail struct {
	Status string `json:"status,omitempty"`
	Data   struct {
		ResultCount int   `json:"resultCount,omitempty"`
		Handle      Asset `json:"adversaryHandle,omitempty"`
	} `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type HandleResource struct {
	TCResource
	asset Asset
}

func NewHandleResource(r TCResource) *HandleResource {
	r.Path("handles")
	return &HandleResource{TCResource: r}
}

func (r *HandleResource) Id(id int) *HandleResource {
	r.asset.ID = id
	r.Path(id)
	return r
}

func (r *HandleResource) Retrieve() ([]Asset, error) {
	if r.asset.ID > 0 {
		grp, err := r.detail()
		grps := []Asset{grp.Data.Handle}
		return grps, err
	}

	grps, err := r.list()
	return grps.Data.Handle, err
}

func (r *HandleResource) detail() (*HandleResponseDetail, error) {
	grp := &HandleResponseDetail{}
	_, err := r.Response(grp).Get()
	return grp, err
}

func (r *HandleResource) list() (*HandleResponseList, error) {
	grp := &HandleResponseList{}
	res, err := r.Response(grp).Get()
	return grp, ResourceError(grp.Message, res, err)
}

func (r *HandleResource) Create(g *Asset) (Asset, error) {
	grp := &HandleResponseDetail{}
	r.Response(grp)
	_, err := r.Post(g)
	return grp.Data.Handle, err
}

func (r *HandleResource) Update(g *Asset) (Asset, error) {
	grp := &HandleResponseDetail{}
	r.Response(grp)
	_, err := r.Put(g)
	return grp.Data.Handle, err
=======
func (r *AssetResource) PhoneNumbers(id ...int) {

}

func (r *AssetResource) Url(id ...int) {

}

func (r *AssetResource) Handles(id ...int) {

>>>>>>> 7f36e8cae6e0e011996ec5a83466db3dd59f9ba7
}
