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
