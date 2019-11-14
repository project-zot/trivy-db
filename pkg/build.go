package pkg

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"

	"github.com/simar7/gokv/encoding"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	bolt "github.com/simar7/gokv/bbolt"
	"github.com/urfave/cli"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	//if err := db.Init(cacheDir); err != nil {
	//	return err
	//}

	kv, err := bolt.NewStore(bolt.Options{
		RootBucketName: "trivy",
		Path:           db.Path(cacheDir),
		Codec:          encoding.JSON,
	})
	if err != nil {
		return err
	}

	targets := c.String("only-update")
	light := c.Bool("light")
	updateInterval := c.Duration("update-interval")
	if err := vulnsrc.Update(*kv, strings.Split(targets, ","), cacheDir, light, updateInterval); err != nil {
		return err
	}

	return nil

}
