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
	"encoding/json"
	"os"

	log "github.com/Sirupsen/logrus"

	"fmt"
	tc "github.com/rangertaha/threatconnect-go/pkg"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("threatconnect")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}

func main() {

	client := tc.New(tc.TCConfig{
		BaseUrl:    viper.GetString("API.BASE_URL"),
		AccessId:   viper.GetString("API.ACCESS_ID"),
		SecretKey:  viper.GetString("API.SECRET_KEY"),
		DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
		Version:    viper.GetString("API.VERSION"),
	})

	seclabel := client.SecurityLabel()
	obj, _, err := seclabel.Get()
	if err != nil {
		log.Error(err)
	}

	j, err := json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	groups := client.Groups().Adversaries("1054439").Attributes("2963621").SecurityLabels()
	obj, _, err = groups.Get()
	if err != nil {
		log.Error(err)
	}

	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

}
