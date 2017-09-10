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
	"testing"

	"github.com/stretchr/testify/assert"
	"encoding/json"


	log "github.com/Sirupsen/logrus"
)

func CheckResponse(t *testing.T ,obj interface{}, res *http.Response, rerr error, msg string) {
	if rerr != nil {
		log.Panic(rerr)
	}

	j, err := json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	t.Log(res.Status, msg)
}


func TestGroups(t *testing.T) {
	TCClient := New(TCConf)

	Groups := TCClient.Groups()
	i, res, err := Groups.Get()
	CheckResponse(t, i, res, err, "/v2/groups")




	assert.IsType(t, i, &GroupResponseList{}, "")
	assert.IsType(t, res, &http.Response{}, "")
	assert.NoError(t, err, "")

	obj := i.(*GroupResponseList)
	assert.Equal(t, obj.Status, "Success", "")
	assert.IsType(t, obj.Data.Groups, []Group{}, "")
}
