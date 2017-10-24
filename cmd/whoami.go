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

	log "github.com/Sirupsen/logrus"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tc "github.com/rangertaha/threatconnect-go/pkg"
)

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show your user information",
	Long:  `Show your user information`,
	Run: func(cmd *cobra.Command, args []string) {
		SetupLogging(viper.GetString("LOGGING.LEVEL"))

		client := tc.New(tc.TCConfig{
			BaseUrl:    viper.GetString("API.BASE_URL"),
			AccessId:   viper.GetString("API.ACCESS_ID"),
			SecretKey:  viper.GetString("API.SECRET_KEY"),
			DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
			Version:    viper.GetString("API.VERSION"),
		})
		obj, _, err := client.WhoAmI().Get()

		if err != nil {
			log.Panic(err)
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetBorder(false)
		table.SetHeader([]string{"UserName", "FirstName", "LastName", "Pseudonym", "Role"})

		v := obj.(*tc.WhoAmIResponseDetail).Data.User
		table.Append([]string{v.UserName, v.FirstName, v.LastName, v.Pseudonym, v.Role})

		table.Render()
	},
}

func init() {
	RootCmd.AddCommand(whoamiCmd)
}
