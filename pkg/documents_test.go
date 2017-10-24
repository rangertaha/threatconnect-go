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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupDocuments(t *testing.T) {
	TCClient := New(TCConf)
	var documentId, attributeID int

	{
		document := &Document{
			Name:     "malwaresample.zip",
			FileName: "golangsample.exe",
			Malware:  true,
			Password: "TCinfected",
		}
		res, err := TCClient.Groups().Documents().Create(document)
		CheckResponse(t, err, "CREATE   /v2/groups/documents")
		documentId = res.Id

		assert.IsType(t, res, Document{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Document Attribute Create"}
		res, err := TCClient.Groups().Documents(documentId).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/documents/"+strconv.Itoa(documentId)+"/attributes")
		attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Document Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		document := &Document{
			Name:     "golangmalwaresample.zip",
			FileName: "golangsample.exe",
			Malware:  true,
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
		res, err := TCClient.Groups().Documents(documentId).Attributes(attributeID).Remove()
		path := "/v2/groups/documents/" + strconv.Itoa(documentId) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Documents(documentId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/documents/"+strconv.Itoa(documentId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
