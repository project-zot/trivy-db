package alpine

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sync"

	"github.com/simar7/gokv"
	kvtypes "github.com/simar7/gokv/types"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	alpineDir = "alpine"
)

var (
	platformFormat = "alpine %s"
)

type VulnSrc struct {
	dbc db.Operations
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(kv gokv.Store, dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", alpineDir)
	var cves []AlpineCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve AlpineCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Alpine JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alpine walk: %w", err)
	}

	if err = vs.save(kv, cves); err != nil {
		return xerrors.Errorf("error in Alpine save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(kv gokv.Store, cves []AlpineCVE) error {
	log.Println("Saving Alpine DB")

	var eg error
	var wg sync.WaitGroup
	for _, cve := range cves {
		go func() {
			wg.Add(1)
			defer wg.Done()
			platformName := fmt.Sprintf(platformFormat, cve.Release)
			pkgName := cve.Package
			advisory := types.Advisory{
				FixedVersion: cve.FixedVersion,
			}

			log.Println("saving alpine advisory...")
			if err := kv.BatchSet(kvtypes.BatchSetItemInput{
				BucketName: platformName,
				Keys:       []string{pkgName},
				Values:     map[string]types.Advisory{cve.VulnerabilityID: advisory},
				//Values: fmt.Sprintf("%s:%s", cve.VulnerabilityID, advisory),
			}); err != nil {
				eg = xerrors.Errorf("failed to save alpine advisory: %w", err)
				return
			}

			log.Println("saving alpine vulnerability...")
			vuln := types.VulnerabilityDetail{
				Title:       cve.Subject,
				Description: cve.Description,
			}

			if err := kv.BatchSet(kvtypes.BatchSetItemInput{
				BucketName: db.VulnerabilityDetailBucket,
				Keys:       []string{cve.VulnerabilityID},
				Values:     map[string]types.VulnerabilityDetail{vulnerability.Alpine: vuln},
				//Values: fmt.Sprintf("%s:%v", vulnerability.Alpine, vuln),
			}); err != nil {
				eg = xerrors.Errorf("failed to save alpine vulnerability: %w", err)
				return
			}

			log.Println("saving alpine vulnerability severity...")
			// for light DB
			if err := kv.BatchSet(kvtypes.BatchSetItemInput{
				BucketName: db.SeverityBucket,
				Keys:       []string{cve.VulnerabilityID},
				Values:     types.SeverityUnknown,
			}); err != nil {
				eg = xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
				return
			}
		}()
		if eg != nil {
			log.Println("one or errors occured while saving vuln info")
		}
	}
	wg.Wait()
	return nil

	//err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
	//	for _, cve := range cves {
	//platformName := fmt.Sprintf(platformFormat, cve.Release)
	//pkgName := cve.Package
	//advisory := types.Advisory{
	//	FixedVersion: cve.FixedVersion,
	//}
	//if err := vs.dbc.PutAdvisory(tx, platformName, pkgName, cve.VulnerabilityID, advisory); err != nil {
	//	return xerrors.Errorf("failed to save alpine advisory: %w", err)
	//}

	//vuln := types.VulnerabilityDetail{
	//	Title:       cve.Subject,
	//	Description: cve.Description,
	//}
	//if err := vs.dbc.PutVulnerabilityDetail(tx, cve.VulnerabilityID, vulnerability.Alpine, vuln); err != nil {
	//	return xerrors.Errorf("failed to save alpine vulnerability: %w", err)
	//}

	// for light DB
	//if err := vs.dbc.PutSeverity(tx, cve.VulnerabilityID, types.SeverityUnknown); err != nil {
	//	return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
	//}
	//}
	//return nil
	//})
	//if err != nil {
	//	return xerrors.Errorf("error in db batch update: %w", err)
	//}
	//return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alpine advisories: %w", err)
	}
	return advisories, nil
}
