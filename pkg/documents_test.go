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

func TestGroupDocuments(t *testing.T) {
	TCClient := New(TCConf)
	var documentId int

	{
		document := &Document{
			Name: "malwaresample.zip",
			FileName: "golangsample.exe",
			Malware: true,
			Password: "TCinfected",
		}
		res, err := TCClient.Groups().Documents().Create(document)
		CheckResponse(t, err, "CREATE   /v2/groups/documents")
		documentId = res.Id

		assert.IsType(t, res, Document{}, "")
		assert.NoError(t, err, "")
	}

	{
		document := &Document{
			Name: "golangmalwaresample.zip",
			FileName: "golangsample.exe",
			Malware: true,
			Password: "TCinfected",
		}
		res, err := TCClient.Groups().Documents(documentId).Update(document)
		CheckResponse(t, err, "UPDATE   /v2/groups/documents/"+strconv.Itoa(documentId))

		assert.IsType(t, res, Document{}, "")
		assert.Equal(t, "golangmalwaresample.zip", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Documents(documentId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/documents/"+strconv.Itoa(documentId))

		assert.IsType(t, res, []Document{}, "")
		assert.Equal(t, "golangmalwaresample.zip", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Documents(documentId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/documents/"+strconv.Itoa(documentId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
