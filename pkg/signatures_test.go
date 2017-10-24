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

func TestGroupSignatures(t *testing.T) {
	TCClient := New(TCConf)
	var signatureId, attributeID int

	{
		signature := &Signature{
			Name:     "Golang Client",
			FileName: "golangclient.txt",
			FileType: "Snort",
			FileText: "Golang Client",
		}

		res, err := TCClient.Groups().Signatures().Create(signature)
		CheckResponse(t, err, "CREATE   /v2/groups/signatures")
		signatureId = res.Id

		assert.IsType(t, res, Signature{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Signature Attribute Create"}
		res, err := TCClient.Groups().Signatures(signatureId).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/signatures/"+strconv.Itoa(signatureId)+"/attributes")
		attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Signature Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		signature := &Signature{
			Name:     "Golang Client Update",
			FileName: "golangclient.txt",
			FileType: "Snort",
			FileText: "Golang Client Update",
		}
		res, err := TCClient.Groups().Signatures(signatureId).Update(signature)
		CheckResponse(t, err, "UPDATE   /v2/groups/signatures/"+strconv.Itoa(signatureId))

		assert.IsType(t, res, Signature{}, "")
		assert.Equal(t, "Golang Client Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Signatures(signatureId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/signatures/"+strconv.Itoa(signatureId))

		assert.IsType(t, res, []Signature{}, "")
		assert.Equal(t, "Golang Client Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Signatures(signatureId).Attributes(attributeID).Remove()
		path := "/v2/groups/incidents/" + strconv.Itoa(signatureId) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Signatures(signatureId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/signatures/"+strconv.Itoa(signatureId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
