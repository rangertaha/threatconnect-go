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
