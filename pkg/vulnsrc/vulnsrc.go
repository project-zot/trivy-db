package vulnsrc

import (
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/simar7/gokv"
	kvtypes "github.com/simar7/gokv/types"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"

	"github.com/aquasecurity/trivy-db/pkg/db"
	//bolt "github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

type Updater interface {
	Update(gokv.Store, string) error
}

var (
	sources = []string{vulnerability.Nvd, vulnerability.RedHat, vulnerability.Debian,
		vulnerability.DebianOVAL, vulnerability.Alpine, vulnerability.Amazon,
		vulnerability.RubySec, vulnerability.RustSec, vulnerability.PhpSecurityAdvisories,
		vulnerability.NodejsSecurityWg, vulnerability.PythonSafetyDB}
)

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[string]Updater{
		//vulnerability.Nvd:    nvd.NewVulnSrc(),
		vulnerability.Alpine: alpine.NewVulnSrc(),
		//vulnerability.RedHat: redhat.NewVulnSrc(),
		//vulnerability.RedHatOVAL:            redhatoval.NewVulnSrc(),
		//vulnerability.Debian: debian.NewVulnSrc(),
		//vulnerability.DebianOVAL:            debianoval.NewVulnSrc(),
		//vulnerability.Ubuntu: ubuntu.NewVulnSrc(),
		//vulnerability.Amazon: amazon.NewVulnSrc(),
		//vulnerability.RubySec:               bundler.NewVulnSrc(),
		//vulnerability.PhpSecurityAdvisories: composer.NewVulnSrc(),
		//vulnerability.NodejsSecurityWg:      node.NewVulnSrc(),
		//vulnerability.PythonSafetyDB:        python.NewVulnSrc(),
		//vulnerability.RustSec:               cargo.NewVulnSrc(),
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	for distribution := range updateMap {
		UpdateList = append(UpdateList, distribution)
	}
}

func Update(kv gokv.Store, targets []string, cacheDir string, light bool, updateInterval time.Duration) error {
	log.Println("Updating vulnerability database...")

	for _, distribution := range targets {
		vulnSrc, ok := updateMap[distribution]
		if !ok {
			return xerrors.Errorf("%s does not supported yet", distribution)
		}
		log.Printf("Updating %s data...\n", distribution)

		if err := vulnSrc.Update(kv, cacheDir); err != nil {
			return xerrors.Errorf("error in %s update: %w", distribution, err)
		}
	}

	dbType := db.TypeFull
	if light {
		dbType = db.TypeLight
	}

	err := kv.Set(kvtypes.SetItemInput{
		BucketName: "metadata",
		Key:        "data",
		Value: db.Metadata{
			Version:    db.SchemaVersion,
			Type:       dbType,
			NextUpdate: time.Now().UTC().Add(updateInterval),
			UpdatedAt:  time.Now().UTC(),
		},
	})
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
	}

	log.Println(">> scanning all keys: ")
	so, err := kv.Scan(kvtypes.ScanInput{BucketName: db.VulnerabilityDetailBucket})
	if err != nil {
		return xerrors.Errorf("failed to put vulnerability: %w", err)
	}

	log.Println(">> unmarshalling values...")
	vulns := map[string]map[string]types.VulnerabilityDetail{}
	for i, cveID := range so.Keys {
		var vulnMap map[string]types.VulnerabilityDetail
		if err := json.Unmarshal(so.Values[i], &vulnMap); err != nil {
			log.Println("failed to unmarshal Vulnerability JSON: %w", err)
			vulns[cveID] = nil
			continue
		}
		vulns[cveID] = vulnMap
	}

	log.Println(">> adding back to trivy db..")
	var wg sync.WaitGroup
	for cveID, vulnMap := range vulns {
		go func(cveID string, vulnMap map[string]types.VulnerabilityDetail) {
			wg.Add(1)
			defer wg.Done()
			severity, title, description, references := getSeverity(vulnMap), getTitle(vulnMap), getDescription(vulnMap), getReferences(vulnMap)
			vuln := types.Vulnerability{
				Title:       title,
				Description: description,
				Severity:    severity.String(),
				References:  references,
			}

			if err := kv.BatchSet(kvtypes.BatchSetItemInput{
				BucketName: "details-bucket",
				Keys:       []string{cveID},
				Values:     vuln,
			}); err != nil {
				log.Println("failed to save vuln: ", err)
			}
		}(cveID, vulnMap)
	}

	wg.Wait()

	//if light {
	//	return optimizeLightDB(kv)
	//}
	//return optimizeFullDB(kv)

	return nil
}

func getSeverity(details map[string]types.VulnerabilityDetail) types.Severity {
	for _, source := range sources {
		switch d, ok := details[source]; {
		case !ok:
			continue
		case d.CvssScore > 0:
			return scoreToSeverity(d.CvssScore)
		case d.CvssScoreV3 > 0:
			return scoreToSeverity(d.CvssScoreV3)
		case d.Severity != 0:
			return d.Severity
		case d.SeverityV3 != 0:
			return d.SeverityV3
		}
	}
	return types.SeverityUnknown
}

func getTitle(details map[string]types.VulnerabilityDetail) string {
	for _, source := range sources {
		d, ok := details[source]
		if !ok {
			continue
		}
		if d.Title != "" {
			return d.Title
		}
	}
	return ""
}

func getDescription(details map[string]types.VulnerabilityDetail) string {
	for _, source := range sources {
		d, ok := details[source]
		if !ok {
			continue
		}
		if d.Description != "" {
			return d.Description
		}
	}
	return ""
}

func getReferences(details map[string]types.VulnerabilityDetail) []string {
	references := map[string]struct{}{}
	for _, source := range sources {
		// Amazon contains unrelated references
		if source == vulnerability.Amazon {
			continue
		}
		d, ok := details[source]
		if !ok {
			continue
		}
		for _, ref := range d.References {
			// e.g. "\nhttps://curl.haxx.se/docs/CVE-2019-5481.html\n    "
			ref = strings.TrimSpace(ref)
			for _, r := range strings.Split(ref, "\n") {
				references[r] = struct{}{}
			}
		}
	}
	var refs []string
	for ref := range references {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i] < refs[j]
	})
	return refs
}

func scoreToSeverity(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.SeverityCritical
	case score >= 7.0:
		return types.SeverityHigh
	case score >= 4.0:
		return types.SeverityMedium
	case score > 0.0:
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

//func optimizeFullDB(dbc db.Config) error {Saving Alpine DB
//	err := dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
//		severity, title, description, references := vulnerability.GetDetail(cveID)
//		vuln := types.Vulnerability{
//			Title:       title,
//			Description: description,
//			Severity:    severity.String(),
//			References:  references,
//		}
//		if err := dbc.PutVulnerability(tx, cveID, vuln); err != nil {
//			return xerrors.Errorf("failed to put vulnerability: %w", err)
//		}
//		return nil
//	})
//	if err != nil {
//		return xerrors.Errorf("failed to iterate vulnerability: %w", err)
//	}
//
//	if err := dbc.DeleteSeverityBucket(); err != nil {
//		return xerrors.Errorf("failed to delete severity bucket: %w", err)
//	}
//
//	if err := dbc.DeleteVulnerabilityDetailBucket(); err != nil {
//		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
//	}
//
//	return nil
//
//}

//
//func optimizeLightDB(dbc db.Config) error {
//	err := dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
//		// get correct severity
//		sev, _, _, _ := vulnerability.GetDetail(cveID)
//
//		// overwrite unknown severity with correct severity
//		if err := dbc.PutSeverity(tx, cveID, sev); err != nil {
//			return xerrors.Errorf("failed to put severity: %w", err)
//		}
//		return nil
//	})
//	if err != nil {
//		return xerrors.Errorf("failed to iterate severity: %w", err)
//	}
//
//	if err = dbc.DeleteVulnerabilityDetailBucket(); err != nil {
//		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
//	}
//	return nil
//}
