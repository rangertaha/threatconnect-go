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

package cmd

import (
	"os"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tc "github.com/rangertaha/threatconnect-go/pkg"
)

// adversariesCmd represents the adversaries command
var adversariesCmd = &cobra.Command{
	Use:   "adversaries",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		SetupLogging(viper.GetString("LOGGING.LEVEL"))

		client := tc.New(tc.TCConfig{
			BaseUrl:    viper.GetString("API.BASE_URL"),
			AccessId:   viper.GetString("API.ACCESS_ID"),
			SecretKey:  viper.GetString("API.SECRET_KEY"),
			DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
			Version:    viper.GetString("API.VERSION"),
		})
		obj, _, err := client.Groups().Adversaries().Get()

		if err != nil {
			log.Panic(err)
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetBorder(false)
		table.SetHeader([]string{"ID", "DateAdded", "Name", "Owner", "Type", "Link"})

		for _, v := range obj.(*tc.AdversaryResponseList).Data.Groups {
			table.Append([]string{strconv.Itoa(v.Id), v.DateAdded, v.Name, v.OwnerName, v.Type, v.WebLink})
		}
		table.Render()

	},
}

func init() {
	groupsCmd.AddCommand(adversariesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// adversariesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	adversariesCmd.Flags().StringP("adversary", "a", "", "Adversary ID")
	adversariesCmd.Flags().StringP("filters", "f", "", "Filters the security labels results")

}
