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
	//"net/http"
	
	"github.com/spf13/viper"
	log "github.com/Sirupsen/logrus"
	

	tc "github.com/rangertaha/threatconnect-go/pkg"
	"net/http"
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

func check(res *http.Response, err error, msg string) {
	logging := log.WithFields(
		log.Fields{
			"code": res.StatusCode,
			"status": res.Status,
			//"body": string(res.Body),
		})
	if err != nil {
		logging.Error(err, msg)

	} else {
		logging.Info(res.Status, msg)
	}
}

func main() {
	client := tc.New(tc.TCConfig{
		BaseUrl:    viper.GetString("API.BASE_URL"),
		AccessId:   viper.GetString("API.ACCESS_ID"),
		SecretKey:  viper.GetString("API.SECRET_KEY"),
		DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
		Version:    viper.GetString("API.VERSION"),
	})

	//     /v2/groups/{type}/{id}
	//     /v2/groups/{type}/{id}/attributes
	//     /v2/groups/{type}/{id}/attributes/{attributeId}
	//     /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels
	//     /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels/{securityLabel}

	//     /v2/groups/{type}/{id}/groups
	//     /v2/groups/{type}/{id}/groups/{associatedGroupType}
	//     /v2/groups/{type}/{id}/groups/{associatedGroupType}/{associatedGroupId}

	//     /v2/groups/{type}/{id}/indicators
	//     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}
	//     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}/{associatedIndicator}

	//     /v2/groups/{type}/{id}/publish
	//     /v2/groups/{type}/{id}/securityLabels
	//     /v2/groups/{type}/{id}/securityLabels/{securityLabel}

	//     /v2/groups/{type}/{id}/tags
	//     /v2/groups/{type}/{id}/tags/{tagName}

	//     /v2/groups/{type}/{id}/victimAssets
	//     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}
	//     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}/{assetId}

	//     /v2/groups/{type}/{id}/victims
	//     /v2/groups/{type}/{id}/victims/{victimId}


	{
		//     /v2/groups
		res, err := client.Groups().Get()
		check(res, err, "  GET:  /v2/groups")
	}

	{
		//grp := &tc.Group{Name: "Taha's Golang Group"}
		//res, err := client.Groups().Adversaries().Post(grp)
		//check(res, err, "  POST:  /v2/groups/adversaries")
	}


	//{
	//	//     /v2/groups/{type}
	//	obj, res, err := client.Groups().Adversaries().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}
	//	obj, res, err := client.Groups().Adversaries(1054439).Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439")
	//}


	//{
	//	//     /v2/groups/{type}/{id}/attributes
	//	obj, res, err := client.Groups().Adversaries(1054439).Attributes().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/attributes/{attributeId}
	//	obj, res, err := client.Groups().Adversaries(1054439).Attributes("2963621").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/attributes/2963621")
	//
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels
	//	obj, res, err := client.Groups().Adversaries(1054439).Attributes("2963621").SecurityLabels().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/attributes/2963621")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/attributes/{attributeId}/securityLabels/{securityLabel}
	//	//obj, res, err := client.Groups().Adversaries(1054439).Attributes("2963621").SecurityLabels("{securityLabel}").Get()
	//	//check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/attributes/2963621/securityLabels/{securityLabel}")
	//}
	//
	//
	//
	//
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/groups
	//	obj, res, err := client.Groups().Adversaries(1054439).Groups().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/groups")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/groups/{associatedGroupType}
	//	obj, res, err := client.Groups().Adversaries(1054439).Groups().AssociatedType("signatures").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/groups/signatures")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/groups/{associatedGroupType}/{associatedGroupId}
	//	obj, res, err := client.Groups().Adversaries(1054439).Groups().AssociatedType("signatures").AssociatedId("1149415").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/groups/signatures/1149415")
	//}
	//// -----------------------------------------------------------------------
	//
	//
	//
	////     /v2/groups/{type}/{id}/indicators
	////     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}
	////     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}/{associatedIndicator}
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/indicators
	//	obj, res, err := client.Groups().Adversaries(1054439).Indicators().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/indicators")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}
	//	obj, res, err := client.Groups().Adversaries(1054439).Indicators().AssociatedType("addresses").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/indicators/addresses")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/indicators/{associatedIndicatorType}/{associatedIndicator}
	//	obj, res, err := client.Groups().Adversaries(1054439).Indicators().AssociatedType("addresses").AssociatedId("17463458").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/indicators/addresses/17463458")
	//}
	//
	//
	////     /v2/groups/{type}/{id}/publish
	////     /v2/groups/{type}/{id}/securityLabels
	////     /v2/groups/{type}/{id}/securityLabels/{securityLabel}
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/publish
	//	//obj, res, err := client.Groups().Adversaries(1054439).Publish().Get()
	//	//check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/publish")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/securityLabels
	//	obj, res, err := client.Groups().Adversaries(1054439).SecurityLabels().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/securityLabels")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/securityLabels/{securityLabel}
	//	obj, res, err := client.Groups().Adversaries(1054439).SecurityLabels("TLP Green").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/securityLabels/TLP Green")
	//}
	//
	//
	//
	////     /v2/groups/{type}/{id}/tags
	////     /v2/groups/{type}/{id}/tags/{tagName}
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/tags
	//	obj, res, err := client.Groups().Adversaries(1054439).Tags().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/tags")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/tags/{tagName}
	//	obj, res, err := client.Groups().Adversaries(1054439).Tags("DoNotDelete").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/tags/DoNotDelete")
	//}
	//
	//
	////     /v2/groups/{type}/{id}/victimAssets
	////     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}
	////     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}/{assetId}
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/victimAssets
	//	obj, res, err := client.Groups().Adversaries(1054439).VictimAssets().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/victimAssets")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}
	//	obj, res, err := client.Groups().Adversaries(1054439).VictimAssets().Type("emailAddresses").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/victimAssets/emailAddresses")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/victimAssets/{victimAssetType}/{assetId}
	//	obj, res, err := client.Groups().Adversaries(1054439).VictimAssets().Type("emailAddresses").Id("265").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/victimAssets/emailAddresses/265")
	//}
	//
	//
	////     /v2/groups/{type}/{id}/victims
	////     /v2/groups/{type}/{id}/victims/{victimId}
	//// -----------------------------------------------------------------------
	//{
	//	//     /v2/groups/{type}/{id}/victims
	//	obj, res, err := client.Groups().Adversaries(1054439).Victims().Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/victims")
	//}
	//
	//{
	//	//     /v2/groups/{type}/{id}/victims/{victimId}
	//	obj, res, err := client.Groups().Adversaries(1054439).Victims("172").Get()
	//	check(obj, res, err, "  GET:  /v2/groups/adversaries/1054439/victims/172")
	//}

}
