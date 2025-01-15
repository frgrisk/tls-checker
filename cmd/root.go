package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "tls-checker",
		Short: "A TLS client/server application",
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tlsapp.yaml)")
	rootCmd.PersistentFlags().String("cert", "cert.pem", "Path to certificate file")
	rootCmd.PersistentFlags().String("key", "key.pem", "Path to private key file")
	rootCmd.PersistentFlags().String("ca", "rootCA.pem", "Path to root CA certificate")
	rootCmd.PersistentFlags().String("addr", "localhost:8443", "Address to serve on or connect to")

	viper.BindPFlag("cert", rootCmd.PersistentFlags().Lookup("cert"))
	viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))
	viper.BindPFlag("ca", rootCmd.PersistentFlags().Lookup("ca"))
	viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("addr"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".tlsapp")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
