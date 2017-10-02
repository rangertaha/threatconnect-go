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
	"errors"
	"fmt"
	"net/http"
	//"encoding/json"

	log "github.com/Sirupsen/logrus"
	"io"
	"io/ioutil"
)

func PrettyPrintJson(data io.ReadCloser) {

	body, err := ioutil.ReadAll(data)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}

	fmt.Printf("%s", body)

	//var prettyJSON bytes.Buffer
	//
	//err := json.Indent(&prettyJSON, body, "", "\t")
	//if err != nil {
	//	log.Warn("Pretty print JSON parse error: ", err)
	//}
	//if log.GetLevel() == log.DebugLevel {
	//	fmt.Println(string(prettyJSON.Bytes()))
	//}
}

func ResourceError(msg string, response *http.Response, rerr error) error {
	if rerr != nil {
		return rerr

	}
	if msg != "" {
		return errors.New(msg)
	}
	return nil
}
