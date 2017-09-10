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

//
//import (
//	//"net/url"
//	"path"
//	"net/http"
//
//	log "github.com/Sirupsen/logrus"
//)
//
//type Resourcer interface {
//	Path(string)  *Resource
//	Get() (interface{}, *http.Response, error)
//	Put() (interface{}, *http.Response, error)
//	Post() (interface{}, *http.Response, error)
//	Delete() (interface{}, *http.Response, error)
//	Append(*Resource) *Resource
//}
//
//
//type Resource struct {
//	TC        *ThreatConnectClient
//	Seg       string
//	Filters  []string
//	Body     interface{}
//	Response interface{}
//}
//
//func (r *Resource) Path(segment string) *Resource {
//	r.Seg = path.Join(r.Seg, segment)
//	return r
//}
//
//func (r *Resource) Append(res Resource) *Resource {
//	r.Seg = path.Join(r.Seg, res.Seg)
//	r.Filters = append(r.Filters, res.Filters...)
//	return r
//}
//
//func (r *Resource) Get() (interface{}, *http.Response, error) {
//	logging := log.WithFields(log.Fields{"function": "Get", "method": "GET"})
//
//	rpath := path.Join(r.Seg, r.Seg)
//
//	r.TC.Client = r.TC.Authenticate("GET", rpath)
//	res, err := r.TC.Client.ReceiveSuccess(r.Response)
//
//	logging = logging.WithFields(
//		log.Fields{"code": res.StatusCode, "length": res.ContentLength})
//	if err != nil {
//		logging.Error(err)
//	}
//	logging.Debug(res.Status)
//
//	return r.Response, res, err
//}
//
//func (r *Resource) Put() (interface{}, *http.Response, error) {
//	return nil, nil, nil
//}
//
//func (r *Resource) Post() (interface{}, *http.Response, error) {
//	return nil, nil, nil
//}
//
//func (r *Resource) Delete() (interface{}, *http.Response, error) {
//	return nil, nil, nil
//}
//
