package dnsprovider

import (
	"context"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"log"
)

func NewCloudFlareProvider(apiKey string) DnsProvider {
	api, err := cloudflare.NewWithAPIToken(apiKey)
	if err != nil {
		log.Fatal(err)
	}
	return &CloudFlareProvider{
		api: api,
	}
}

type CloudFlareProvider struct {
	api *cloudflare.API
}

func (c *CloudFlareProvider) CreateDnsTextEntry(zone string, name string, content string) error {
	ctx := context.Background()

	id, err := c.api.ZoneIDByName(zone)
	if err != nil {
		return err
	}

	records, err := c.api.DNSRecords(ctx, id, cloudflare.DNSRecord{
		Type: "TXT",
		Name: name,
	})

	if len(records) == 0 {
		ent, err := c.api.CreateDNSRecord(ctx, id, cloudflare.DNSRecord{
			Type: "TXT",
			Name: name,
			Content: content,
		})
		if err != nil {
			return err
		}
		fmt.Println(ent)
	} else if len(records) == 1 {
		err = c.api.UpdateDNSRecord(ctx, id, records[0].ID, cloudflare.DNSRecord{
			Type: "TXT",
			Name: name,
			Content: content,
		})
		if err != nil {
			return err
		}
	}

	return nil
}