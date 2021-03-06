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

func TestGroupCampaigns(t *testing.T) {
	TCClient := New(TCConf)
	var campaignId, attributeID int

	{
		campaign := &Campaign{Name: "Golang Client"}

		res, err := TCClient.Groups().Campaigns().Create(campaign)
		CheckResponse(t, err, "CREATE   /v2/groups/campaigns")
		campaignId = res.Id

		assert.IsType(t, res, Campaign{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Campaign Attribute Create"}
		res, err := TCClient.Groups().Campaigns(campaignId).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/campaigns/"+strconv.Itoa(campaignId)+"/attributes")
		attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Campaign Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		campaign := &Campaign{Name: "Golang Client Update"}
		res, err := TCClient.Groups().Campaigns(campaignId).Update(campaign)
		CheckResponse(t, err, "UPDATE   /v2/groups/campaigns/"+strconv.Itoa(campaignId))

		assert.IsType(t, res, Campaign{}, "")
		assert.Equal(t, "Golang Client Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Campaigns(campaignId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/campaigns/"+strconv.Itoa(campaignId))

		assert.IsType(t, res, []Campaign{}, "")
		assert.Equal(t, "Golang Client Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Campaigns(campaignId).Attributes(attributeID).Remove()
		path := "/v2/groups/campaigns/" + strconv.Itoa(campaignId) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Campaigns(campaignId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/campaigns/"+strconv.Itoa(campaignId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
