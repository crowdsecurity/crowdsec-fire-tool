package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	flag "github.com/spf13/pflag"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func intPtr(i int) *int {
	return &i
}

func config(k *koanf.Koanf) error {
	var prefix = "CROWDSEC_FIRE_"

	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}

	f.StringSlice("config", []string{}, "Config file(s) to use")
	f.String("cti_key", "", "CTI API Key")
	if err := f.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("error parsing flags: %v", err)
	}

	cFiles, _ := f.GetStringSlice("config")
	for _, c := range cFiles {
		if err := k.Load(file.Provider(c), yaml.Parser()); err != nil {
			return fmt.Errorf("error loading file: %v", err)
		}
	}

	if err := k.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, prefix))
	}), nil); err != nil {
		return fmt.Errorf("error loading env: %v", err)
	}

	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		return fmt.Errorf("error loading flags: %v", err)
	}

	// validate config

	if k.String("cti_key") == "" {
		return fmt.Errorf("a CTI key is required. Please set CROWDSEC_FIRE_CTI_KEY=<key> or a fire.yml config file with 'cti_key: <key>'")
	}

	return nil
}

func main() {
	var k = koanf.New(".")

	if err := config(k); err != nil {
		log.Fatal(err)
	}

	cti_key := k.String("cti_key")

	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(cti_key))
	paginator := cticlient.NewFirePaginator(client, cticlient.FireParams{
		Limit: intPtr(1000),
	})

	for {
		items, err := paginator.Next()
		if err != nil {
			log.Fatalf("Error whilst fetching CTI data got %s", err.Error())
		}
		if items == nil {
			break
		}

		for _, item := range items {
			os.Stdout.WriteString(item.Ip + "\n")
		}
	}
}
