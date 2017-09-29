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

package main

import (
	"os"
	"fmt"
	"bytes"
	"encoding/json"

	"github.com/spf13/viper"
	log "github.com/Sirupsen/logrus"

	tc "github.com/rangertaha/threatconnect-go/pkg"

)

func init() {
	viper.SetConfigName("threatconnect")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	if logLevel, err := log.ParseLevel(viper.GetString("LOGGING.LEVEL")); err == nil {
		log.SetLevel(logLevel)
	}
	log.SetOutput(os.Stdout)
	//log.SetLevel(log.InfoLevel)
}

func jsonPrettyPrint(in string) string {
    var out bytes.Buffer
    err := json.Indent(&out, []byte(in), "", "\t")
    if err != nil {
        return in
    }
    return out.String()
}

func main() {
	client := tc.New(tc.TCConfig{
		BaseUrl:    viper.GetString("API.BASE_URL"),
		AccessId:   viper.GetString("API.ACCESS_ID"),
		SecretKey:  viper.GetString("API.SECRET_KEY"),
		DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
		Version:    viper.GetString("API.VERSION"),
	})

	{
		//     /v2/groups
		client.Groups().Get()
	}

	{
		//     /v2/groups
		_, err := client.Groups().Retrieve()
		fmt.Println(err, "  GET:  /v2/groups")
		//fmt.Println(res)
		//fmt.Println(err)
	}

}
