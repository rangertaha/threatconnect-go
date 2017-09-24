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
	"fmt"
	"path"
	"net/http"
	"encoding/json"

	log "github.com/Sirupsen/logrus"
)

type QueryParams struct {
	Filters string `json:"filters,omitempty"`
}

type TCResponse struct {
	Status string `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

func NewResponse(status, message string) *TCResponse {
	return  &TCResponse{Status: status, Message: message}
}

func (r *TCResponse) Failure(err error) {
	r.Status = "Failure"
	r.Message = err.Error()
}

func (r *TCResponse) Success() {
	r.Status = "Success"
}




type Resourcer interface {
	Path()
	Body()
	Method()
	Filter()
	Request()
	Get()
	Post()
	Put()
	Delete()
}



type TCResource struct {
	TC        *ThreatConnectClient
	base     string
	path      string
	method 	  string
	params    interface{}
	body      interface{}
	RResponse interface{}
}

func (r *TCResource) Path(paths ...interface{}) *TCResource {
	var spaths []string
	for _, p := range paths {
		spaths = append(spaths,fmt.Sprint(p))
	}
	r.path = path.Join(r.path, path.Join(spaths...))
	return r
}

func (r *TCResource) Body(b interface{}) *TCResource {
	r.body = b
	return r
}

func (r *TCResource) Method(method string) *TCResource {
	r.method = method
	return r
}

func (r *TCResource) Filter(filters ...string) *TCResource {
	// Need improving
	r.params = &QueryParams{Filters: filters[0]}
	return r
}

func (r *TCResource) uri(paths ...string) string {
	return path.Join(r.base, r.path, path.Join(paths...))
}


func (r *TCResource) Request() (*TCResponse, *http.Response, error) {
	r.TC.Client = r.TC.Authenticate(r.method, r.uri())

	response := new(TCResponse)

	res, err := r.TC.Client.QueryStruct(r.params).
		BodyJSON(r.body).Receive(response, response)

	log.Error(res.Status, res.Body, res.StatusCode)
	if err != nil {
		response.Failure(err)
		log.Error("Client:", err)
		return response, err
	}

	var data json.RawMessage
	err = json.Unmarshal(response.Data, &data)
	if err != nil {
		log.Error("Json:", err)
		response.Failure(err)
		return response, err
	}

	logging := log.WithFields(
		log.Fields{
			"method": r.method,
			"code": res.StatusCode,
			"length": res.ContentLength,
			"status": response.Status,
			"message": response.Message,
			"uri": r.uri(),
		})

	logging.Info("Requested resouce")
	return response, res, nil
}


func (r *TCResource) Get() (*TCResponse, error) {
	return r.Method("GET").Request()
}

func (r *TCResource) Post(body interface{}) (*TCResponse, error) {
	return r.Method("POST").Body(body).Request()
}

func (r *TCResource) Put(body interface{}) (*TCResponse, error) {
	return r.Method("PUT").Body(body).Request()
}

func (r *TCResource) Delete() (*TCResponse, error) {
	return r.Method("DELETE").Request()
}
