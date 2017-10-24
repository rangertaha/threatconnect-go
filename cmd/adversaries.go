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
