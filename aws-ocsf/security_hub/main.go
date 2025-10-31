package main

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"security_hub/internal/tangent/logs/log"
	"security_hub/internal/tangent/logs/mapper"
	"security_hub/tangenthelpers"

	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "aws-securityhub → ocsf.vulnerability_finding",
			Version: "0.1.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("Id"),
					mapper.PredHas("Title"),
				}),
				None: cm.ToList([]mapper.Pred{}),
			},
		})
	}

	mapper.Exports.ProcessLogs = func(input cm.List[log.Logview]) (res cm.Result[cm.List[uint8], cm.List[uint8], string]) {
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			lv := log.Logview(items[idx])

			var f types.AwsSecurityFinding

			if v := tangenthelpers.GetString(lv, "Id"); v != nil {
				f.Id = v
			}
			if v := tangenthelpers.GetString(lv, "Title"); v != nil {
				f.Title = v
			}
			if v := tangenthelpers.GetString(lv, "Description"); v != nil {
				f.Description = v
			}
			if v := tangenthelpers.GetString(lv, "CreatedAt"); v != nil {
				f.CreatedAt = v
			}
			if v := tangenthelpers.GetString(lv, "UpdatedAt"); v != nil {
				f.UpdatedAt = v
			}

			if v := tangenthelpers.GetString(lv, "Workflow.Status"); v != nil {
				var wf types.Workflow
				switch *v {
				case string(types.WorkflowStatusNew):
					wf.Status = types.WorkflowStatusNew
				case string(types.WorkflowStatusNotified):
					wf.Status = types.WorkflowStatusNotified
				case string(types.WorkflowStatusSuppressed):
					wf.Status = types.WorkflowStatusSuppressed
				case string(types.WorkflowStatusResolved):
					wf.Status = types.WorkflowStatusResolved
				default:
					wf.Status = types.WorkflowStatusNew
				}
				f.Workflow = &wf
			}

			if v := tangenthelpers.GetString(lv, "Severity.Label"); v != nil {
				var sev types.Severity
				switch *v {
				case string(types.SeverityLabelInformational):
					sev.Label = types.SeverityLabelInformational
				case string(types.SeverityLabelLow):
					sev.Label = types.SeverityLabelLow
				case string(types.SeverityLabelMedium):
					sev.Label = types.SeverityLabelMedium
				case string(types.SeverityLabelHigh):
					sev.Label = types.SeverityLabelHigh
				case string(types.SeverityLabelCritical):
					sev.Label = types.SeverityLabelCritical
				default:
					sev.Label = types.SeverityLabelLow
				}
				f.Severity = &sev
			}

			if vals, ok := tangenthelpers.GetStringList(lv, "Types"); ok {
				f.Types = vals
			}

			// Arrays: Resources and Vulnerabilities
			resources := buildResourcesFromLogview(lv)

			severity, severityID := mapSecurityHubSeverity(f.Severity)
			status, statusID := mapSecurityHubStatus(f.Workflow)

			var createdAt *time.Time
			if f.CreatedAt != nil {
				if t, err := time.Parse(time.RFC3339, *f.CreatedAt); err == nil {
					createdAt = &t
				}
			}

			var updatedAt *time.Time
			if f.UpdatedAt != nil {
				if t, err := time.Parse(time.RFC3339, *f.UpdatedAt); err == nil {
					updatedAt = &t
				}
			}

			var endTime *time.Time
			if status == "closed" && updatedAt != nil {
				endTime = updatedAt
			}

			vendorName := "AWS"
			productName := "SecurityHub"

			var fixAvailable bool
			if f.Remediation != nil && f.Remediation.Recommendation != nil {
				fixAvailable = true
			}

			var remediation *ocsf.Remediation
			if f.Remediation != nil {
				var description string
				if f.Remediation.Recommendation != nil && f.Remediation.Recommendation.Text != nil {
					description = *f.Remediation.Recommendation.Text
				}
				var references []string
				if f.Remediation.Recommendation != nil && f.Remediation.Recommendation.Url != nil {
					references = append(references, *f.Remediation.Recommendation.Url)
				}
				remediation = &ocsf.Remediation{Desc: description, References: references}
			}

			var title string
			if f.Title != nil {
				title = *f.Title
			}

			var lastSeenTime *time.Time
			if updatedAt != nil {
				lastSeenTime = updatedAt
			}

			var createdTimeInt, lastSeenTimeInt int64
			if createdAt != nil {
				createdTimeInt = createdAt.UnixMilli()
			}
			if lastSeenTime != nil {
				lastSeenTimeInt = lastSeenTime.UnixMilli()
			}

			var vulnerabilities []ocsf.VulnerabilityDetails
			cwe := mapSecurityHubCWE(f)
			if nPtr := tangenthelpers.Len(lv, "Vulnerabilities"); nPtr != nil && *nPtr > 0 {
				n := int(*nPtr)
				vulnerabilities = make([]ocsf.VulnerabilityDetails, 0, n)
				for i := 0; i < n; i++ {
					cve := mapCVEFromLogviewAt(lv, i)
					vulnerabilities = append(vulnerabilities, ocsf.VulnerabilityDetails{
						Cwe:                cwe,
						Cve:                cve,
						Desc:               f.Description,
						Title:              &title,
						Severity:           &severity,
						IsExploitAvailable: boolPtr(false),
						FirstSeenTime:      createdTimeInt,
						IsFixAvailable:     &fixAvailable,
						LastSeenTime:       lastSeenTimeInt,
						VendorName:         &vendorName,
						Remediation:        remediation,
					})
				}
			} else {
				vulnerabilities = []ocsf.VulnerabilityDetails{
					{
						Cwe:                cwe,
						Cve:                mapCVEsFromLogview(lv),
						Desc:               f.Description,
						Title:              &title,
						Severity:           &severity,
						IsExploitAvailable: boolPtr(false),
						FirstSeenTime:      createdTimeInt,
						IsFixAvailable:     &fixAvailable,
						LastSeenTime:       lastSeenTimeInt,
						VendorName:         &vendorName,
						Remediation:        remediation,
					},
				}
			}

			var activityID int32
			var activityName string
			var typeUID int64
			var typeName string
			var eventTime time.Time
			className := "Vulnerability Finding"
			categoryUID := int32(2)
			categoryName := "Findings"
			classUID := int32(2002)

			if timesEqualStrPtr(f.UpdatedAt, f.CreatedAt) {
				activityID = int32(1)
				activityName = "Create"
				typeUID = int64(classUID)*100 + int64(activityID)
				typeName = "Vulnerability Finding: Create"
				if createdAt != nil {
					eventTime = *createdAt
				} else {
					eventTime = time.Now().UTC()
				}
			} else if status == "closed" && endTime != nil {
				activityID = int32(3)
				activityName = "Close"
				typeUID = int64(classUID)*100 + int64(activityID)
				typeName = "Vulnerability Finding: Close"
				eventTime = *endTime
			} else {
				activityID = int32(2)
				activityName = "Update"
				typeUID = int64(classUID)*100 + int64(activityID)
				typeName = "Vulnerability Finding: Update"
				if updatedAt != nil {
					eventTime = *updatedAt
				} else if createdAt != nil {
					eventTime = *createdAt
				} else {
					eventTime = time.Now().UTC()
				}
			}

			metadata := ocsf.Metadata{
				Product: ocsf.Product{
					Name:       &productName,
					VendorName: &vendorName,
				},
				Version: "1.5.0",
			}

			var modifiedTimeInt int64
			if updatedAt != nil {
				modifiedTimeInt = updatedAt.UnixMilli()
			}

			var endTimeInt int64
			if endTime != nil {
				endTimeInt = endTime.UnixMilli()
			}

			findingInfo := ocsf.FindingInformation{
				Uid:           strDeref(f.Id),
				Title:         f.Title,
				Desc:          f.Description,
				CreatedTime:   createdTimeInt,
				FirstSeenTime: createdTimeInt,
				LastSeenTime:  lastSeenTimeInt,
				ModifiedTime:  modifiedTimeInt,
				DataSources:   []string{"securityhub"},
				Types:         []string{"Vulnerability"},
			}

			out := ocsf.VulnerabilityFinding{
				Time:            eventTime.UnixMilli(),
				StartTime:       createdTimeInt,
				EndTime:         endTimeInt,
				ActivityId:      activityID,
				ActivityName:    &activityName,
				CategoryUid:     categoryUID,
				CategoryName:    &categoryName,
				ClassUid:        classUID,
				ClassName:       &className,
				Message:         f.Description,
				Metadata:        metadata,
				Resources:       resources,
				Status:          &status,
				StatusId:        &statusID,
				TypeUid:         typeUID,
				TypeName:        &typeName,
				Vulnerabilities: vulnerabilities,
				FindingInfo:     findingInfo,
				SeverityId:      int32(severityID),
				Severity:        &severity,
			}

			line, err := json.Marshal(out)
			if err != nil {
				res.SetErr(err.Error())
				return
			}

			buf.Write(line)
			buf.WriteByte('\n')
		}

		res.SetOK(cm.ToList(buf.Bytes()))
		bufPool.Put(buf)
		return
	}
}

func init() {
	Wire()
}

func main() {}

// ---------------- helpers ----------------

func buildResourcesFromLogview(v log.Logview) []ocsf.ResourceDetails {
	opt := v.GetList("Resources")
	if opt.None() {
		return nil
	}
	lst := opt.Value()
	out := make([]ocsf.ResourceDetails, 0, lst.Len())
	for i := 0; i < int(lst.Len()); i++ {
		tp := tangenthelpers.GetString(v, fmt.Sprintf("Resources[%d].Type", i))
		id := tangenthelpers.GetString(v, fmt.Sprintf("Resources[%d].Id", i))
		if id == nil || *id == "" {
			continue
		}
		out = append(out, ocsf.ResourceDetails{Uid: id, Type: tp})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildAwsVulnsFromLogview(v log.Logview) []types.Vulnerability {
	nPtr := tangenthelpers.Len(v, "Vulnerabilities")
	if nPtr == nil || *nPtr == 0 {
		return nil
	}
	n := int(*nPtr)
	vulns := make([]types.Vulnerability, 0, n)
	for i := 0; i < n; i++ {
		var vuln types.Vulnerability
		vuln.Id = tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Id", i))

		// Cvss list
		mPtr := tangenthelpers.Len(v, fmt.Sprintf("Vulnerabilities[%d].Cvss", i))
		if mPtr != nil && *mPtr > 0 {
			m := int(*mPtr)
			cvss := make([]types.Cvss, 0, m)
			for j := 0; j < m; j++ {
				var c types.Cvss
				c.BaseScore = tangenthelpers.GetFloat64(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].BaseScore", i, j))
				c.Version = tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].Version", i, j))
				c.BaseVector = tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].BaseVector", i, j))
				cvss = append(cvss, c)
			}
			vuln.Cvss = cvss
		}

		// ReferenceUrls
		if refs, ok := tangenthelpers.GetStringList(v, fmt.Sprintf("Vulnerabilities[%d].ReferenceUrls", i)); ok {
			vuln.ReferenceUrls = refs
		}

		vulns = append(vulns, vuln)
	}
	if len(vulns) == 0 {
		return nil
	}
	return vulns
}

func mapCVEsFromLogview(v log.Logview) *ocsf.CVE {
	nPtr := tangenthelpers.Len(v, "Vulnerabilities")
	if nPtr == nil || *nPtr == 0 {
		return nil
	}
	id := tangenthelpers.GetString(v, "Vulnerabilities[0].Id")
	if id == nil || *id == "" {
		return nil
	}
	refs, _ := tangenthelpers.GetStringList(v, "Vulnerabilities[0].ReferenceUrls")
	var scores []ocsf.CVSSScore
	mPtr := tangenthelpers.Len(v, "Vulnerabilities[0].Cvss")
	if mPtr != nil && *mPtr > 0 {
		m := int(*mPtr)
		for j := 0; j < m; j++ {
			base := tangenthelpers.GetFloat64(v, fmt.Sprintf("Vulnerabilities[0].Cvss[%d].BaseScore", j))
			ver := tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[0].Cvss[%d].Version", j))
			vec := tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[0].Cvss[%d].BaseVector", j))
			if base != nil && ver != nil {
				s := ocsf.CVSSScore{BaseScore: *base, Version: *ver}
				if vec != nil {
					s.VectorString = vec
				}
				scores = append(scores, s)
			}
		}
	}
	return &ocsf.CVE{Uid: *id, References: refs, Cvss: scores}
}

func mapCVEFromLogviewAt(v log.Logview, i int) *ocsf.CVE {
	id := tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Id", i))
	if id == nil || *id == "" {
		return nil
	}
	refs, _ := tangenthelpers.GetStringList(v, fmt.Sprintf("Vulnerabilities[%d].ReferenceUrls", i))
	var scores []ocsf.CVSSScore
	mPtr := tangenthelpers.Len(v, fmt.Sprintf("Vulnerabilities[%d].Cvss", i))
	if mPtr != nil && *mPtr > 0 {
		m := int(*mPtr)
		for j := 0; j < m; j++ {
			base := tangenthelpers.GetFloat64(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].BaseScore", i, j))
			ver := tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].Version", i, j))
			vec := tangenthelpers.GetString(v, fmt.Sprintf("Vulnerabilities[%d].Cvss[%d].BaseVector", i, j))
			if base != nil && ver != nil {
				s := ocsf.CVSSScore{BaseScore: *base, Version: *ver}
				if vec != nil {
					s.VectorString = vec
				}
				scores = append(scores, s)
			}
		}
	}
	return &ocsf.CVE{Uid: *id, References: refs, Cvss: scores}
}

func mapSecurityHubSeverity(severity *types.Severity) (string, int) {
	if severity == nil {
		return "unknown", 0
	}
	switch severity.Label {
	case types.SeverityLabelInformational:
		return "informational", 1
	case types.SeverityLabelLow:
		return "low", 2
	case types.SeverityLabelMedium:
		return "medium", 3
	case types.SeverityLabelHigh:
		return "high", 4
	case types.SeverityLabelCritical:
		return "critical", 5
	default:
		return "unknown", 0
	}
}

func mapSecurityHubStatus(workflow *types.Workflow) (string, int32) {
	if workflow == nil {
		return "open", 1
	}
	switch workflow.Status {
	case types.WorkflowStatusNew, types.WorkflowStatusNotified:
		return "open", 1
	case types.WorkflowStatusSuppressed:
		return "suppressed", 3
	case types.WorkflowStatusResolved:
		return "closed", 4
	default:
		return "unknown", 0
	}
}

func mapSecurityHubCVE(finding types.AwsSecurityFinding) *ocsf.CVE {
	if len(finding.Vulnerabilities) > 0 {
		for _, vuln := range finding.Vulnerabilities {
			if vuln.Id != nil && vuln.Cvss != nil && len(vuln.Cvss) > 0 {
				var cvss []ocsf.CVSSScore
				for _, c := range vuln.Cvss {
					if c.BaseScore != nil && c.Version != nil {
						cvss = append(cvss, ocsf.CVSSScore{
							BaseScore:    *c.BaseScore,
							VectorString: c.BaseVector,
							Version:      *c.Version,
						})
					}
				}
				var references []string
				if vuln.ReferenceUrls != nil {
					references = vuln.ReferenceUrls
				}
				return &ocsf.CVE{Uid: *vuln.Id, References: references, Cvss: cvss}
			}
		}
	}
	return nil
}

func mapSecurityHubCWE(finding types.AwsSecurityFinding) *ocsf.CWE {
	if finding.Types != nil {
		for _, t := range finding.Types {
			if len(t) > 4 && t[:4] == "CWE-" {
				url := "https://cwe.mitre.org/data/definitions/" + t[4:] + ".html"
				return &ocsf.CWE{Uid: t, SrcUrl: &url}
			}
		}
	}
	return nil
}

func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func boolPtr(v bool) *bool { return &v }

func timesEqualStrPtr(a, b *string) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
