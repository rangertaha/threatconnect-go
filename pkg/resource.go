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


package threatconnect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	log "github.com/Sirupsen/logrus"
)

type QueryParams struct {
	Filters string `json:"filters,omitempty"`
}

type TCResponse struct {
	Status  string          `json:"status,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Message string          `json:"message,omitempty"`
}

type DeleteResponse struct {
	ApiCalls    int    `json:"apiCalls,omitempty"`
	ResultCount int    `json:"resultCount,omitempty"`
	Status      string `json:"status,omitempty"`
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
	TC     *ThreatConnectClient
	base   string
	path   string
	method string
	params interface{}
	body   interface{}
	resp   interface{}
	data   interface{}
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
	//body := &res.Body
	//PrettyPrintJson(*body)

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
	return r.Method("POST").Body(body).Request()
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
