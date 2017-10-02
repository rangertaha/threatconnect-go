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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupThreat(t *testing.T) {
	TCClient := New(TCConf)
	var threatId int

	{
		threat := &Threat{Name: "Golang Client Threat Group"}

		res, err := TCClient.Groups().Threats().Create(threat)
		CheckResponse(t, err, "CREATE   /v2/groups/threats")
		threatId = res.Id

		assert.IsType(t, res, Threat{}, "")
		assert.NoError(t, err, "")
	}

	{
		threat := &Threat{Name: "Golang Client Threat Group Update"}
		res, err := TCClient.Groups().Threats(threatId).Update(threat)
		CheckResponse(t, err, "UPDATE   /v2/groups/threats/"+strconv.Itoa(threatId))

		assert.IsType(t, res, Threat{}, "")
		assert.Equal(t, "Golang Client Threat Group Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Threats(threatId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/threats/"+strconv.Itoa(threatId))

		assert.IsType(t, res, []Threat{}, "")
		assert.Equal(t, "Golang Client Threat Group Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Threats(threatId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/threats/"+strconv.Itoa(threatId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
