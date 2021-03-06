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
		attributeID = res.ID

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

func TestGroupAdversaryAssetPhoneNumbers(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, phoneNumberID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{PhoneNumber: "123-123-1234"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().PhoneNumbers().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers")
		phoneNumberID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().PhoneNumbers().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{PhoneNumber: "999-999-9999"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

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

func TestGroupAdversaryAssetUrls(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, urlID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Url: "http://example.com/golang/testing"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Urls().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls")
		urlID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Urls().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Url: "http://example.com/golang/testing/updating"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Urls(urlID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Urls(urlID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Urls(urlID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

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

func TestGroupAdversaryAssetHandles(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, handlesID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Groups().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Handle: "example handles"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Handles().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles")
		handlesID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Handles().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Handle: "example handle updates"}
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Handles(handlesID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Handles(handlesID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Adversaries(adversaryID).Assets().Handles(handlesID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

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

func TestGroupAssociatedAdversary(t *testing.T) {
	TCClient := New(TCConf)
	var adversaries []Adversary
	{
		res, err := TCClient.Groups().Adversaries().Retrieve()
		adversaries = res

		assert.IsType(t, res, []Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range adversaries {
			res, err := TCClient.Groups().Adversaries(s.ID).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, Adversary{}, "")
			assert.IsType(t, res, []Adversary{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.Groups().Adversaries(s.ID).Groups().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups")

				assert.IsType(t, res, []Group{}, "")
				assert.NoError(t, err, "")
			}

			{
				res, err := TCClient.Groups().Adversaries(s.ID).Groups().Adversaries().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups/adversaries")

				assert.IsType(t, res, []Adversary{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.Groups().Adversaries(s.ID).Groups().Adversaries(g.ID).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups/adversaries/"+strconv.Itoa(g.ID))

					assert.IsType(t, res, []Adversary{}, "")
					assert.NoError(t, err, "")
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------------------

func TestIndicatorAdversaries(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}

		res, err := TCClient.Indicators().Adversaries().Create(adversary)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries")
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		incident := &Adversary{Name: "Golang Adversary Update"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Update(incident)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, []Adversary{}, "")
		assert.Equal(t, "Golang Adversary Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
func TestIndicatorAdversaryAttributes(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, attributeID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Indicators().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		attribute := &Attribute{Type: "Description", Value: "Golang Adversary Attribute Create"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Attributes().Create(attribute)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/attributes")
		attributeID = res.ID

		assert.IsType(t, res, Attribute{}, "")
		assert.Equal(t, "Description", res.Type, "")
		assert.Equal(t, "Golang Adversary Attribute Create", res.Value, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Attributes(attributeID).Remove()
		path := "/v2/groups/adversaries/" + strconv.Itoa(adversaryID) + "/attributes/" + strconv.Itoa(attributeID)
		CheckResponse(t, err, "DELETE   "+path)
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}

func TestIndicatorAdversaryAssetPhoneNumbers(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, phoneNumberID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Indicators().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{PhoneNumber: "123-123-1234"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().PhoneNumbers().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers")
		phoneNumberID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().PhoneNumbers().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{PhoneNumber: "999-999-9999"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().PhoneNumbers(phoneNumberID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/phoneNumbers/"+strconv.Itoa(phoneNumberID))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")

		assert.NoError(t, err, "")
	}

}

func TestIndicatorAdversaryAssetUrls(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, urlID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Indicators().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Url: "http://example.com/golang/testing"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Urls().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls")
		urlID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Urls().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Url: "http://example.com/golang/testing/updating"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Urls(urlID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Urls(urlID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Urls(urlID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/urls/"+strconv.Itoa(urlID))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}

func TestIndicatorAdversaryAssetHandles(t *testing.T) {
	TCClient := New(TCConf)
	var adversaryID, handlesID int

	{
		adversary := &Adversary{Name: "Golang Adversary"}
		res, err := TCClient.Indicators().Adversaries().Create(adversary)
		adversaryID = res.ID

		assert.IsType(t, res, Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Handle: "example handles"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Handles().Create(asset)
		CheckResponse(t, err, "CREATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles")
		handlesID = res.ID

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Handles().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles")

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		asset := &Asset{Handle: "example handle updates"}
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Handles(handlesID).Update(asset)
		CheckResponse(t, err, "UPDATE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

		assert.IsType(t, res, Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Handles(handlesID).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

		assert.IsType(t, res, []Asset{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Assets().Handles(handlesID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID)+"/adversaryAssets/handles/"+strconv.Itoa(handlesID))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Indicators().Adversaries(adversaryID).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/adversaries/"+strconv.Itoa(adversaryID))
		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}

func TestIndicatorAssociatedAdversary(t *testing.T) {
	TCClient := New(TCConf)
	var adversaries []Adversary
	{
		res, err := TCClient.Indicators().Adversaries().Retrieve()
		adversaries = res

		assert.IsType(t, res, []Adversary{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range adversaries {
			res, err := TCClient.Indicators().Adversaries(s.ID).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, Adversary{}, "")
			assert.IsType(t, res, []Adversary{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.Indicators().Adversaries(s.ID).Indicators().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups")

				assert.IsType(t, res, []Indicator{}, "")
				assert.NoError(t, err, "")
			}

			{
				res, err := TCClient.Indicators().Adversaries(s.ID).Indicators().Adversaries().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups/adversaries")

				assert.IsType(t, res, []Adversary{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.Indicators().Adversaries(s.ID).Indicators().Adversaries(g.ID).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/groups/adversaries/"+strconv.Itoa(s.ID)+"/groups/adversaries/"+strconv.Itoa(g.ID))

					assert.IsType(t, res, []Adversary{}, "")
					assert.NoError(t, err, "")
				}
			}
		}
	}
}
