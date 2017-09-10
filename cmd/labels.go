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
	"fmt"

	"github.com/spf13/cobra"
)

var labelsCmd = &cobra.Command{
	Use:   "labels",
	Short: "Provides a means to designate information stored within ThreatConnect as sensitive.",
	Long:  `Security Labels included in the ThreatConnect platform provide a means to designate information stored within ThreatConnect as sensitive. When sharing data with partners, or when copying data to and from Communities, Security Labels provide control over what is shared and allow the sharer to redact information based on Security Labels that are applicable to Indicators, Attributes, Groups, Tasks, Tracks, and Victims.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Security Labels called")
	},
}

func init() {
	RootCmd.AddCommand(labelsCmd)

	// Security Labels flags which will only run when this command is called
	labelsCmd.Flags().StringP("filters", "f", "", "Filters the security labels results")
}
