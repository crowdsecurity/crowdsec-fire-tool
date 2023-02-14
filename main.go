package main

import (
	"log"
	"os"
	"path"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

func intPtr(i int) *int {
	return &i
}

func main() {
	client := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(os.Getenv("CTI_API_KEY")))
	paginator := cticlient.NewFirePaginator(client, cticlient.FireParams{
		Limit: intPtr(1000),
	})

	outputDir := os.Getenv("OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "./"
	}

	filePath := path.Join(outputDir, "fire.txt")
	file, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for {
		items, err := paginator.Next()
		if err != nil {
			if err == cticlient.ErrUnauthorized {
				os.Remove(filePath)
			}
			log.Fatalf("Error whilst fetching CTI data got %s", err.Error())
		}
		if items == nil {
			break
		}

		for _, item := range items {
			file.WriteString(item.Ip + "\n")
		}
	}
}
