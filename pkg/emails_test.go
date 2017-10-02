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

func TestGroupEmails(t *testing.T) {
	TCClient := New(TCConf)
	var emailId int

	{
		email := &Email{
			Name:    "Golang Client Email Group",
			Header:  "Golang Client",
			Subject: "Golang Client",
			Body:    "Golang Client",
		}

		res, err := TCClient.Groups().Emails().Create(email)
		CheckResponse(t, err, "CREATE   /v2/groups/emails")
		emailId = res.Id

		assert.IsType(t, res, Email{}, "")
		assert.NoError(t, err, "")
	}

	{
		email := &Email{Name: "Golang Client Email Group Update"}
		res, err := TCClient.Groups().Emails(emailId).Update(email)
		CheckResponse(t, err, "UPDATE   /v2/groups/emails/"+strconv.Itoa(emailId))

		assert.IsType(t, res, Email{}, "")
		assert.Equal(t, "Golang Client Email Group Update", res.Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Emails(emailId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/groups/emails/"+strconv.Itoa(emailId))

		assert.IsType(t, res, []Email{}, "")
		assert.Equal(t, "Golang Client Email Group Update", res[0].Name, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Groups().Emails(emailId).Remove()
		CheckResponse(t, err, "DELETE   /v2/groups/emails/"+strconv.Itoa(emailId))

		assert.IsType(t, res, &DeleteResponse{}, "")
		assert.NoError(t, err, "")
	}

}
