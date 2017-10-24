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
	"fmt"
	"os"
	//"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"

	tc "github.com/rangertaha/threatconnect-go/pkg"
	group "github.com/rangertaha/threatconnect-go/pkg/groups"
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

func check(err error, msg string) {
	logging := log.WithFields(
		log.Fields{
			"status": status,
			//"body": string(res.Body),
		})
	if err != nil {
		logging.Error(err, msg)

	} else {
		logging.Info(status, msg)
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
	grp := &group.Group{Name: "Taha's Golang Group"}
	{
		res, err := client.Groups().Adversaries().Create(grp)
		check(err, "  POST:  /v2/groups/adversaries")
		fmt.Println(res)
		fmt.Println(err)
	}

	{
		//     /v2/groups
		res, err := client.Groups().Retrieve()
		//check(res, err, "  GET:  /v2/groups")
		fmt.Println(res)
		fmt.Println(err)
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
