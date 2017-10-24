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
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"

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

func main() {
	client := tc.New(tc.TCConfig{
		BaseUrl:    viper.GetString("API.BASE_URL"),
		AccessId:   viper.GetString("API.ACCESS_ID"),
		SecretKey:  viper.GetString("API.SECRET_KEY"),
		DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
		Version:    viper.GetString("API.VERSION"),
	})

	var adversaryId int
	{
		adversary := &tc.Adversary{Name: "Golang Client"}
		res, err := client.Groups().Adversaries().Create(adversary)
		adversaryId = res.Id
		fmt.Println("CREATE")
		fmt.Println("Id", res.Id)
		fmt.Println("Name", res.Name)
		fmt.Println("OwnerName", res.OwnerName)
		fmt.Println("Error", err)
	}

	{
		res, err := client.Groups().Adversaries(adversaryId).Retrieve()
		fmt.Println("RETRIEVE")
		for _, i := range res {
			fmt.Println("Id", i.Id)
			fmt.Println("Name", i.Name)
			fmt.Println("OwnerName", i.OwnerName)
		}
		fmt.Println("Error", err)
	}

	{
		adversary := &tc.Adversary{Name: "Golang Client Update"}
		res, err := client.Groups().Adversaries(adversaryId).Update(adversary)
		fmt.Println("UPDATE")
		fmt.Println("Id", res.Id)
		fmt.Println("Name", res.Name)
		fmt.Println("OwnerName", res.OwnerName)
		fmt.Println("Error", err)
	}

	{
		res, err := client.Groups().Adversaries(adversaryId).Retrieve()
		fmt.Println("RETRIEVE")
		for _, i := range res {
			fmt.Println("Id", i.Id)
			fmt.Println("Name", i.Name)
			fmt.Println("OwnerName", i.OwnerName)
		}
		fmt.Println("Error", err)
	}

	{
		res, err := client.Groups().Adversaries(adversaryId).Remove()
		fmt.Println("apiCalls", res.ApiCalls)
		fmt.Println("Status", res.Status)
		fmt.Println("resultCount", res.ResultCount)
		fmt.Println("Error", err)
	}

}
