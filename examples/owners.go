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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"

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

	//  /v2/owners
	//  /v2/owners/mine
	//  /v2/owners/mine/members
	//  /v2/owners/metrics
	//  /v2/owners/{id}/metrics

	log.Debug(client.Config.AccessId)
	log.Debug(client.Config.SecretKey)

	owners := client.Owners()
	obj, _, err := owners.Get()

	log.Error(err)
	j, err := json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	mine := client.Owners().Mine()
	obj, _, err = mine.Get()
	//fmt.Println(res)
	fmt.Println(err)
	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	metrics := client.Owners().Metrics()
	obj, _, err = metrics.Get()
	//fmt.Println(res)
	fmt.Println(err)
	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	me := client.Owners("445")
	obj, _, err = me.Get()
	//fmt.Println(res)
	fmt.Println(err)
	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	metrics = client.Owners("445").Metrics()
	obj, _, err = metrics.Get()
	//fmt.Println(res)
	fmt.Println(err)
	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

	mem := client.Owners().Mine().Members()
	obj, _, err = mem.Get()
	if err != nil {
		log.Error(err)
	}

	j, err = json.Marshal(&obj)
	if err != nil {
		log.Panic(err)
	}
	log.Debug(string(j))

}
