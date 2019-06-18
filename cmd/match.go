/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/benrlewis/pcaptimeshifter/internal"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

// matchCmd represents the match command
var matchCmd = &cobra.Command{
	Use:   "match [original pcap] [modified pcap] [output file]",
	Short: "Match the timestamps of a source capture to a given output capture",
	Long: `Processes the timestamps from a given pcap file and attach them to the same packets from another capture file.
			Useful for analysing thresholding etc. after processing or recapturing packets in some other way`,
	Run: func(cmd *cobra.Command, args []string) {
		fileArgs := internal.FileArgs{SourceFile: args[0], ModifiedFile: args[1], OutputFile: args[2]}
		logrus.WithFields(logrus.Fields{"Source File": fileArgs.SourceFile, "Modified File": fileArgs.ModifiedFile, "OutputFile": fileArgs.ModifiedFile}).Info("Loading files...")

		if !checkFileExists(fileArgs.SourceFile) || !checkFileExists(fileArgs.ModifiedFile) {
			logrus.Errorln("File(s) not found, please check and try again")
			err := cmd.Usage()
			if err != nil {
				logrus.Fatalln(err)
			}
			os.Exit(1)
		}
		if checkFileExists(fileArgs.OutputFile) && !ForceWrite {
			logrus.Errorln("Output File exists already, use -f to force overwriting")
			err := cmd.Usage()
			if err != nil {
				logrus.Fatalln(err)
			}
			os.Exit(1)
		}
		logrus.Debugln("Found files")
		// We've done the basic sanity checks
		in, out, err := internal.ComparePcaps(fileArgs, 1)
		if err != nil {
			logrus.Fatalf("Error encountered: %v\n", err)
		}
		logrus.Infof("Found %d packets and altered %d packets\n", in, out)
	},
	Args: cobra.ExactArgs(3),
}

func init() {
	rootCmd.AddCommand(matchCmd)
}

func checkFileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
