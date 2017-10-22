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
	var adversaryID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}

		res, err := TCClient.Groups().Adversaries().Create(adversary)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries")
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		incident := &Adversary{Name: "Golang Adversary Update"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Update(incident)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, []Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
func TestGroupAdversaryAttributes(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, attributeID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Adversary Attribute Create"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/attributes")
		//attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Adversary Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Attributes(attributeID).Remove()
		path := "/v2/groups/adversaries/" + strconv.Itoa(adversaryID) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}

func TestGroupAdversaryAssets(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
