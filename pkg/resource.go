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

package threatconnect

import (
	"net/http"
	"errors"
	"path"

	log "github.com/Sirupsen/logrus"

	"encoding/json"
	"fmt"
)

//type TCResponse struct {
//	Status string `json:"status,omitempty"`
//	Data   json.RawMessage `json:"data,omitempty"`
//}

type TCResponse struct {
	Status string `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type TCResourcer interface {
	Path(string) *TCResource
	//Get() (interface{}, *http.Response, error)
	//Append(*TCResource) *TCResource
}

type TCResource struct {
	TC        *ThreatConnectClient
	//Prefix
	//Path
	//Postfix
	RBase     string
	RPath     string
	path      string
	RType     string
	RId       string
	RFilters  []string
	RBody     interface{}
	RResponse interface{}
}

//func (r *TCResource) FullPath(path string) string {
//	baseURL, baseErr := url.Parse(r.RBase)
//	pathURL, pathErr := url.Parse(path)
//	if baseErr == nil && pathErr == nil {
//		return baseURL.ResolveReference(pathURL).String()
//	}
//	return ""
//}

func (r *TCResource) Path(paths ...interface{}) *TCResource {
	var spaths []string
	for _, p := range paths {
		spaths = append(spaths,fmt.Sprint(p))
	}
	r.RPath = path.Join(r.RPath, path.Join(spaths...))
	return r
}

//func (r *TCResource) IsParent(path string) bool {
//	return true
//}
//
//func (r *TCResource) Append(res TCResource) *TCResource {
//	r.RBase = path.Join(r.RBase, res.RBase)
//	r.RPath = path.Join(r.RPath, res.RPath)
//	r.RFilters = append(r.RFilters, res.RFilters...)
//	return r
//}


func (r *TCResource) Get(data interface{}) (*http.Response, error) {
	r.TC.Client = r.TC.Authenticate("GET", path.Join(r.RBase, r.RPath))
	response := new(TCResponse)

	res, err := r.TC.Client.ReceiveSuccess(response)

	logging := log.WithFields(
		log.Fields{
			"method": "GET",
			"code": res.StatusCode,
			"length": res.ContentLength,
			"status": response.Status,
			"message": response.Message,
		})

	if err != nil {
		logging.Error(err)

	} else if res.StatusCode > 201 {
		err = errors.New(res.Status)
		logging.Error(err)

	} else if response.Status == "Failure" {
		err = errors.New(response.Message)

	} else {
		err := json.Unmarshal(response.Data, &data)
		if err != nil {
			fmt.Println("error:", err)
		}
	}

	return res, err
}
