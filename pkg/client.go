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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/dghubble/sling"
	log "github.com/Sirupsen/logrus"
)

type ThreatConnectClient struct {
	Config TCConfig
	Client *sling.Sling
}

type Signature struct {
	Timestamp int64
	Unsigned  string
	Signed    string
}

type TCConfig struct {
	BaseUrl    string
	SecretKey  string
	AccessId   string
	DefaultOrg string
	Version    string
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.ErrorLevel)
}

func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func New(c TCConfig) ThreatConnectClient {
	httpClient := &http.Client{}
	return ThreatConnectClient{
		Config: c,
		Client: sling.New().Client(httpClient).Base(c.BaseUrl),
	}
}

func (t *ThreatConnectClient) Authenticate(method, rpath string) *sling.Sling {
	logging := log.WithFields(log.Fields{"function": "Authenticate"})

	rurl, err := url.Parse(t.Config.BaseUrl)
	if err != nil {
		log.Fatal(err)
	}
	rurl.Path = path.Join(rurl.Path, rpath)
	signature := fmt.Sprintf("%s:%s:%d", rurl.RequestURI(), method, time.Now().Unix())
	signed := computeHmac256(signature, t.Config.SecretKey)

	client := t.Client.
		Set("Timestamp", fmt.Sprintf("%d", time.Now().Unix())).
		Set("Authorization", fmt.Sprintf("TC %s:%s", t.Config.AccessId, signed))

	reqUrl := rurl.String()
	logging = logging.WithFields(log.Fields{"path": reqUrl, "method": method})
	logging.Debug("Authenticating resource")
	if method == "GET" {
		return client.New().Get(reqUrl)
	}
	if method == "POST" {
		return client.New().Post(reqUrl)
	}
	if method == "PUT" {
		fmt.Println("PUT", reqUrl)
		return client.New().Put(reqUrl)
	}
	if method == "DELETE" {
		return client.New().Delete(reqUrl)
	}
	return client
}

//func (t *ThreatConnectClient) Resource(method, path string) *ThreatConnectClient {
//	t.Client = t.Authenticate(method, path)
//	return t
//}

func (t *ThreatConnectClient) Owners(id ...string) *OwnerResource {
	return NewOwners(t).Owners(id...)
}

func (t *ThreatConnectClient) Groups() *GroupResource {
	return &GroupResource{
		TCResource: TCResource{
			TC:   t,
			base: path.Join(t.Config.Version, "groups"),
		},
	}
}

func (t *ThreatConnectClient) SecurityLabel(id ...string) *SecurityLabelsResource {
	resource := &SecurityLabelsResource{
		TCResource{
			TC:   t,
			base: path.Join(t.Config.Version, "securityLabels"),
			resp: new(SecurityLabelResponseList),
		},
	}
	return resource.SecurityLabels(id...)
}

func (t *ThreatConnectClient) WhoAmI() *WhoAmIResource {
	return NewWhoAmI(t).WhoAmI()
}

func (t *ThreatConnectClient) Tags(id ...string) *TagsResource {
	resource := &TagsResource{
		TCResource{
			TC:   t,
			base: path.Join(t.Config.Version, "tags"),
			//RResponse: new(SecurityLabelResponseList),
		},
	}
	return resource.Tags(id...)
}
