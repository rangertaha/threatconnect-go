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

// groupsCmd represents the groups command
var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Groups represent a collection of related behavior and/or intelligence",
	Long:  `Groups represent a collection of related behavior and/or intelligence`,
	Run: func(cmd *cobra.Command, args []string) {
		SetupLogging(viper.GetString("LOGGING.LEVEL"))

		client := tc.New(tc.TCConfig{
			BaseUrl:    viper.GetString("API.BASE_URL"),
			AccessId:   viper.GetString("API.ACCESS_ID"),
			SecretKey:  viper.GetString("API.SECRET_KEY"),
			DefaultOrg: viper.GetString("API.DEFAULT_ORG"),
			Version:    viper.GetString("API.VERSION"),
		})
		obj, _, err := client.Groups().Get()

		if err != nil {
			log.Panic(err)
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetBorder(false)
		table.SetHeader([]string{"ID", "DateAdded", "Name", "Owner", "Type", "Link"})

		for _, v := range obj.(*tc.GroupResponseList).Data.Groups {
			table.Append([]string{strconv.Itoa(v.Id), v.DateAdded, v.Name, v.OwnerName, v.Type, v.WebLink})
		}
		table.Render()

	},
}

func init() {
	RootCmd.AddCommand(groupsCmd)

	groupsCmd.PersistentFlags().String("name", "", `Filter results by name. Filter operators (=, ^)
		Example:
			threatconnect groups --name=HelpMe
		or
			threatconnect groups --name>HelpMe
	`)
	groupsCmd.PersistentFlags().String("dateAdded", "", "Filter date added. Operators (<, >)")
	groupsCmd.PersistentFlags().String("fileType", "", "Filter results by file type. Operators are (=)")
}
