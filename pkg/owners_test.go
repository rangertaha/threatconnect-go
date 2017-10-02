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

func TestOwners(t *testing.T) {
	TCClient := New(TCConf)
	var ownerId int

	{
		res, err := TCClient.Owners().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/owners")

		assert.IsType(t, res, []Owner{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Owners().Mine().Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/owners/mine")
		ownerId = res[0].Id

		assert.IsType(t, res, []Owner{}, "")
		assert.NoError(t, err, "")
	}

	{
		res, err := TCClient.Owners(ownerId).Retrieve()
		CheckResponse(t, err, "RETRIEVE /v2/owners/"+strconv.Itoa(ownerId))

		assert.IsType(t, res, []Owner{}, "")
		assert.NoError(t, err, "")
	}

}
