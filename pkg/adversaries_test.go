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

func TestGroupAdversaries(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryId int

	{
		adversary := &Adversary{Name: "Golang Adversary"}

		res, err := TCClient.Groups().Adversaries().Create(adversary)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries")
		adversaryId = res.Id

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		incident := &Adversary{Name: "Golang Adversary Update"}
		res, err := TCClient.Groups().Adversaries(adversaryId).Update(incident)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, []Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}

func TestGroupAdversaryAttributes(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryId int
	var attributeId int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryId = res.Id

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		incident := &Adversary{Name: "Golang Adversary Update"}
		res, err := TCClient.Groups().Adversaries(adversaryId).Update(incident)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, []Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
