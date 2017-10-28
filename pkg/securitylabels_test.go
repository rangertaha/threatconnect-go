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

func TestSecurityLabels(t *testing.T) {
	TCClient := New(TCConf)
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/securityLabels")

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}
}

func TestSecurityLabelsGroups(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups")

				assert.IsType(t, res, []Group{}, "")
				assert.NoError(t, err, "")
			}
		}
	}
}

func TestSecurityLabelsAssociatedAdversaries(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups")

				assert.IsType(t, res, []Group{}, "")
				assert.NoError(t, err, "")
			}

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Adversaries().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/adversaries")

				assert.IsType(t, res, []Adversary{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Adversaries(g.ID).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/adversaries/"+strconv.Itoa(g.ID))

					assert.IsType(t, res, []Adversary{}, "")
					assert.NoError(t, err, "")
				}

			}

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Campaigns().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/campaigns") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// 	for _, g := range res {
			// 		res, err := TCClient.SecurityLabels(s.Name).Groups().Campaigns(g.Id).Retrieve()
			// 		CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/campaigns"+strconv.Itoa(g.Id))

			// 		assert.IsType(t, res, Adversary{}, "")
			// 		assert.NoError(t, err, "")
			// 	}

			// }

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Documents().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/documents") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// }

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Emails().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/emails") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// }

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Incidents().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/incidents") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// }

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Signatures().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/signatures") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// }

			// {
			// 	res, err := TCClient.SecurityLabels(s.Name).Groups().Threats().Retrieve()
			// 	CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/threats") //+strconv.Itoa(gt.Id))

			// 	assert.IsType(t, res, []Group{}, "")
			// 	assert.NoError(t, err, "")

			// }

		}

	}

}

func TestSecurityLabelsAssociatedCampaigns(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Campaigns().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/campaigns")

				assert.IsType(t, res, []Campaign{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Campaigns(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/campaigns/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Campaign{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}

func TestSecurityLabelsAssociatedDocuments(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Documents().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/documents")

				assert.IsType(t, res, []Document{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Documents(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/documents/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Document{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}

func TestSecurityLabelsAssociatedEmails(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Emails().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/emails")

				assert.IsType(t, res, []Email{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Emails(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/emails/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Email{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}

func TestSecurityLabelsAssociatedIncedents(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Incidents().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/incidents")

				assert.IsType(t, res, []Incident{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Incidents(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/incidents/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Incident{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}

func TestSecurityLabelsAssociatedSignatures(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Signatures().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/signatures")

				assert.IsType(t, res, []Signature{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Signatures(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/signatures/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Signature{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}

func TestSecurityLabelsAssociatedThreats(t *testing.T) {
	TCClient := New(TCConf)
	var labels []SecurityLabel
	{
		res, err := TCClient.SecurityLabels().Retrieve()
		labels = res

		assert.IsType(t, res, []SecurityLabel{}, "")
		assert.NoError(t, err, "")
	}

	{
		for _, s := range labels {
			res, err := TCClient.SecurityLabels(s.Name).Retrieve()
			// CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name)

			assert.IsType(t, s, SecurityLabel{}, "")
			assert.IsType(t, res, []SecurityLabel{}, "")
			assert.NoError(t, err, "")

			{
				res, err := TCClient.SecurityLabels(s.Name).Groups().Threats().Retrieve()
				CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/threats")

				assert.IsType(t, res, []Threat{}, "")
				assert.NoError(t, err, "")

				for _, g := range res {
					res, err := TCClient.SecurityLabels(s.Name).Groups().Threats(g.Id).Retrieve()
					CheckResponse(t, err, "RETRIEVE /v2/securityLabels/"+s.Name+"/groups/threats/"+strconv.Itoa(g.Id))

					assert.IsType(t, res, []Threat{}, "")
					assert.NoError(t, err, "")
				}

			}
		}

	}

}
