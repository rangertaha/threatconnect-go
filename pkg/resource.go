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
	//"errors"
	"path"

	log "github.com/Sirupsen/logrus"

	//"encoding/json"
	"fmt"

	"encoding/json"
)

type TCResponse struct {
	Status string `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

type Data struct {
	ResultCount int `json:"ResultCount,omitempty"`
	Results map[string]interface{}
}

type TCResource struct {
	TC        *ThreatConnectClient
	RBase     string
	RPath     string
	path      string
	RType     string
	RId       string
	RFilters  []string
	RBody     interface{}
	RResponse interface{}
}

func NewResponse(results interface{}) *TCResponse {
	res := new(TCResponse)
	res.Data.Results = results
	return res
}

func (r *TCResource) Path(paths ...interface{}) *TCResource {
	var spaths []string
	for _, p := range paths {
		spaths = append(spaths,fmt.Sprint(p))
	}
	r.RPath = path.Join(r.RPath, path.Join(spaths...))
	return r
}

func (r *TCResource) Get(data interface{}) (*http.Response, error) {
	r.TC.Client = r.TC.Authenticate("GET", path.Join(r.RBase, r.RPath))
	response := NewResponse(data)

	res, err := r.TC.Client.ReceiveSuccess(response)

	logging := log.WithFields(
		log.Fields{
			"method": "GET",
			"code": res.StatusCode,
			"length": res.ContentLength,
			"status": response.Status,
			"message": response.Message,
			"count": response.Data.ResultCount,
			"results": response.Data.Results,
		})
	logging.Info()



	//if err != nil {
	//	logging.Error(err)
	//
	//} else if res.StatusCode > 201 {
	//	err = errors.New(res.Status)
	//	logging.Error(err)
	//
	//} else if response.Status == "Failure" {
	//	err = errors.New(response.Message)
	//
	//} else {
	//	err := json.Unmarshal(response.Data, &data)
	//	if err != nil {
	//		fmt.Println("error:", err)
	//	}
	//}

	return res, err
}
