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
	"flag"
	"fmt"
	"github.com/spf13/viper"
	"os"

	log "github.com/Sirupsen/logrus"
	"testing"
)

var BaseUrl, AccessId, SecretKey, DefaultOrg, Version string
var TCConf TCConfig

func init() {
	viper.SetConfigName("threatconnect")
	viper.AddConfigPath("..")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	flag.StringVar(&BaseUrl, "url", viper.GetString("API.BASE_URL"), "ThreatConnect's API endpoint.")
	flag.StringVar(&AccessId, "id", viper.GetString("API.ACCESS_ID"), "API Access Id")
	flag.StringVar(&SecretKey, "secret", viper.GetString("API.SECRET_KEY"), "API Secret key")
	flag.StringVar(&DefaultOrg, "org", viper.GetString("API.DEFAULT_ORG"), "Organization")
	flag.StringVar(&Version, "version", viper.GetString("API.VERSION"), "API Version")

	TCConf = TCConfig{
		BaseUrl:    BaseUrl,
		AccessId:   AccessId,
		SecretKey:  SecretKey,
		DefaultOrg: DefaultOrg,
		Version:    Version,
	}
}

func CheckResponse(t *testing.T, err error, msg string) {
	if err != nil {
		log.Error(err)
	} else {
		log.Info(msg)
	}
}
