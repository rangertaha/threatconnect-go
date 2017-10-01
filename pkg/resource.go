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
	"net/http"
	"path"
	//"errors"
	"encoding/json"

	log "github.com/Sirupsen/logrus"
)

type QueryParams struct {
	Filters string `json:"filters,omitempty"`
}

type TCResponse struct {
	Status  string      `json:"status,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type DeleteResponse struct {
	ApiCalls  int      `json:"apiCalls,omitempty"`
	ResultCount    int `json:"resultCount,omitempty"`
	Status string      `json:"status,omitempty"`
}



//func (r *TCResponse) Failure(err error) {
//	r.status = "Failure"
//	r.message = err.Error()
//}
//
//func (r *TCResponse) Success() {
//	r.status = "Success"
//}

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
	TC     *ThreatConnectClient
	base   string
	path   string
	method string
	params interface{}
	body   interface{}
	resp   interface{}
	data  interface{}
}

func (r *TCResource) Path(paths ...interface{}) *TCResource {
	var spaths []string
	for _, p := range paths {
		spaths = append(spaths, fmt.Sprint(p))
	}
	r.path = path.Join(r.path, path.Join(spaths...))
	return r
}

func (r *TCResource) Base(b string) *TCResource {
	r.base = b
	return r
}

func (r *TCResource) Body(b interface{}) *TCResource {
	r.body = b
	return r
}

func (r *TCResource) Response(res interface{}) *TCResource {
	r.resp = res
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

func (r *TCResource) Request() (*http.Response, error) {
	r.TC.Client = r.TC.Authenticate(r.method, r.uri())

	res, err := r.TC.Client.QueryStruct(r.params).
		BodyJSON(r.body).Receive(r.resp, r.resp)

	// In 'debug' pretty print json
	//PrettyPrintJson(res.Body)

	logging := log.WithFields(
		log.Fields{
			"method": r.method,
			"code":   res.StatusCode,
			"length": res.ContentLength,
			"uri":    r.uri(),
			"status": res.Status,
		})

	if err != nil {
		logging.Error(err)
	}

	logging.Debug("Resource requested")
	return res, err
}

func (r *TCResource) Get() (*http.Response, error) {
	return r.Method("GET").Request()
}

func (r *TCResource) Post(body interface{}) (*http.Response, error) {
	res, err := r.Method("POST").Body(body).Request()
	return res, err
}

func (r *TCResource) Put(body interface{}) (*http.Response, error) {
	return r.Method("PUT").Body(body).Request()
}

func (r *TCResource) Delete() (*http.Response, error) {
	return r.Method("DELETE").Request()
}

func (r *TCResource) Remove() (*DeleteResponse, error) {
	del := &DeleteResponse{}
	r.Response(del)
	_, err := r.Method("DELETE").Request()
	return del, err
}


//
//func dataResponse(resp *TCResponse, res *http.Response, err error) (json.RawMessage, error) {
//	if err != nil {
//		log.Error(err)
//	}
//
//	if code := res.StatusCode; 200 <= code && code <= 299 {
//		if resp.Status == "Failure" {
//			err = errors.New(resp.Message)
//
//		} else if resp.Status == "Success" {
//			err = nil
//
//		} else {
//			err = errors.New("Unknowed error")
//		}
//	}
//	return resp.Data, err
//}