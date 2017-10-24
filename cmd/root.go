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
	"os"

	log "github.com/Sirupsen/logrus"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile, AccessId, DefaultOrg, SecretKey, BaseUrl, LogLevel, Version string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "threatconnect",
	Short: "Tool that allows users to access ThreatConnect data from a command-line shell.",
	Long: `Tool that allows users to access ThreatConnect data from a command-line shell.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.threatconnect.conf")
	RootCmd.PersistentFlags().StringVar(&BaseUrl, "base_url", "", "base api endpoint")
	RootCmd.PersistentFlags().StringVar(&AccessId, "access_id", "", "api access id")
	RootCmd.PersistentFlags().StringVar(&SecretKey, "secret_key", "", "api secret key")
	RootCmd.PersistentFlags().StringVar(&DefaultOrg, "org", "", "api default organization")
	RootCmd.PersistentFlags().StringVar(&Version, "version", "v2", "api version")
	RootCmd.PersistentFlags().StringVar(&LogLevel, "log_level", "error", "logging level (panic, fatal, error, warn, info, debug)")

	viper.BindPFlag("LOGGING.LEVEL", RootCmd.PersistentFlags().Lookup("log_level"))
	viper.BindPFlag("API.SECRET_KEY", RootCmd.PersistentFlags().Lookup("secret_key"))
	viper.BindPFlag("API.ACCESS_ID", RootCmd.PersistentFlags().Lookup("access_id"))
	viper.BindPFlag("API.BASE_URL", RootCmd.PersistentFlags().Lookup("base_url"))
	viper.BindPFlag("API.VERSION", RootCmd.PersistentFlags().Lookup("version"))
	viper.BindPFlag("API.DEFAULT_ORG", RootCmd.PersistentFlags().Lookup("org"))
}

// initConfig reads in config file.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".threatconnect" (without extension).
		viper.AddConfigPath(home)

		viper.SetConfigName(".threatconnect")
	}
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	viper.ReadInConfig()
}

func SetupLogging(lvl string) {
	if logLevel, err := log.ParseLevel(lvl); err == nil {
		log.SetLevel(logLevel)
	}
	log.SetOutput(os.Stdout)
}
