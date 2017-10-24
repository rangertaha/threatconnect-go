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

func TestGroupIncidents(t *testing.T) {
	TCClient := New(TCConf)
	var incidentId, attributeID int

	{
		incident := &Incident{Name: "Golang Client"}

		res, err := TCClient.Groups().Incidents().Create(incident)
		CheckResponse(t, err, "CREATE   /v2/groups/incidents")
		incidentId = res.Id

		assert.IsType(t, res, Incident{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Incident Attribute Create"}
		res, err := TCClient.Groups().Incidents(incidentId).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/incidents/"+strconv.Itoa(incidentId)+"/attributes")
		attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Incident Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		incident := &Incident{Name: "Golang Client Update"}
		res, err := TCClient.Groups().Incidents(incidentId).Update(incident)
		CheckResponse(t, err, "UPDATE   /v2/groups/incidents/"+strconv.Itoa(incidentId))

		assert.IsType(t, res, Incident{}, "")
		assert.Equal(t, "Golang Client Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Incidents(incidentId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/incidents/"+strconv.Itoa(incidentId))

		assert.IsType(t, res, []Incident{}, "")
		assert.Equal(t, "Golang Client Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Incidents(incidentId).Attributes(attributeID).Remove()
		path := "/v2/groups/incidents/" + strconv.Itoa(incidentId) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Incidents(incidentId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/incidents/"+strconv.Itoa(incidentId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
