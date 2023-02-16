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
	isatty "github.com/mattn/go-isatty"
	"github.com/schollz/progressbar/v3"
	flag "github.com/spf13/pflag"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func intPtr(i int) *int {
	return &i
}

func config() (*koanf.Koanf, error) {
	var k = koanf.New(".")

	var prefix = "CROWDSEC_FIRE_"

	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}

	f.StringSlice("config", []string{}, "Config file(s) to use")
	f.String("cti_key", "", "CTI API Key")
	f.StringP("output", "o", "", "Output file (- for stdout)")

	if err := f.Parse(os.Args[1:]); err != nil {
		return nil, fmt.Errorf("error parsing flags: %v", err)
	}

	cFiles, _ := f.GetStringSlice("config")
	for _, c := range cFiles {
		if err := k.Load(file.Provider(c), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("error loading file: %v", err)
		}
	}

	if err := k.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, prefix))
	}), nil); err != nil {
		return nil, fmt.Errorf("error loading env: %v", err)
	}

	if err := k.Load(posflag.Provider(f, ".", k), nil); err != nil {
		return nil, fmt.Errorf("error loading flags: %v", err)
	}

	// validate config

	if k.String("cti_key") == "" {
		return nil, fmt.Errorf("a CTI key is required (--cti_key). You can also set CROWDSEC_FIRE_CTI_KEY=<key> or a fire.yml config file with 'cti_key: <key>'")
	}

	if k.String("output") == "" {
		return nil, fmt.Errorf("an output file is required (--output or -o). For stdout, use '-'")
	}

	return k, nil
}

func showProgress() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func readFireDB(cti_key string) (string, error) {
	var ret strings.Builder

	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(cti_key))
	paginator := cticlient.NewFirePaginator(client, cticlient.FireParams{
		Limit: intPtr(1000),
	})

	var bar *progressbar.ProgressBar

	if showProgress() {
		bar = progressbar.Default(-1, "Fetching CTI data")
		defer func() {
			_ = bar.Finish()
		}()
	}

	for {
		items, err := paginator.Next()
		if err != nil {
			return "", fmt.Errorf("while fetching CTI data: %v", err)
		}
		if items == nil {
			break
		}

		if bar != nil {
			_ = bar.Add(len(items))
		}

		for _, item := range items {
			ret.WriteString(item.Ip + "\n")
		}
	}

	return ret.String(), nil
}

func main() {
	k, err := config()
	if err != nil {
		log.Fatal(err)
	}

	outFile := os.Stdout

	cti_key := k.String("cti_key")

	data, err := readFireDB(cti_key)
	if err != nil {
		log.Fatal(err)
	}

	output := k.String("output")
	if output != "-" {
		f, err := os.Create(output)
		if err != nil {
			log.Fatalf("Error whilst creating output file %s", err)
		}
		defer f.Close()
		outFile = f
	}

	_, err = outFile.WriteString(data)
	if err != nil {
		log.Fatalf("Error whilst writing output file %s", err)
	}
}
