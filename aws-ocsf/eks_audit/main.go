package main

import (
	"bytes"
	"sync"
	"time"

	"eks_audit/internal/tangent/logs/log"
	"eks_audit/internal/tangent/logs/mapper"
	"eks_audit/tangenthelpers"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// legacy structs removed in favor of OCSF v1.5 typed model

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta { return mapper.Meta{Name: "eks-audit → ocsf.api_activity", Version: "0.2.0"} }
	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{{Any: cm.ToList([]mapper.Pred{}), All: cm.ToList([]mapper.Pred{mapper.PredHas("verb"), mapper.PredHas("requestURI")}), None: cm.ToList([]mapper.Pred{})}})
	}
	mapper.Exports.ProcessLogs = func(input cm.List[log.Logview]) (res cm.Result[cm.List[uint8], cm.List[uint8], string]) {
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			lv := log.Logview(items[idx])

			// Times
			var stage time.Time
			if v := tangenthelpers.GetString(lv, "stageTimestamp"); v != nil {
				if t, err := time.Parse(time.RFC3339Nano, *v); err == nil {
					stage = t.UTC()
				}
			}
			// requestReceivedTimestamp intentionally unused in 1.5 output

			// Actor (OCSF)
			var act ocsf.Actor
			if v := tangenthelpers.GetString(lv, "user.username"); v != nil {
				act.User = &ocsf.User{Name: v}
			}
			// Set app/service context for EKS API server
			act.AppName = stringPtr("kube-apiserver")

			// API (OCSF)
			api := ocsf.API{Operation: get(lv, "verb"), Service: &ocsf.Service{Name: stringPtr("kube-apiserver")}}

			// HTTP (we don't include http_request in 1.5 minimal output)

			// Resources
			var resources []ocsf.ResourceDetails
			if n := get(lv, "objectRef.name"); n != "" {
				resources = append(resources, ocsf.ResourceDetails{
					Name: stringPtr(n),
					Type: stringPtr(get(lv, "objectRef.resource")),
					Uid:  stringPtr(n),
				})
			}

			// Source endpoint
			se := ocsf.NetworkEndpoint{}
			if ip := get(lv, "sourceIPs[0]"); ip != "" {
				se.Ip = stringPtr(ip)
			}

			// Metadata
			md := ocsf.Metadata{Version: "1.5.0", CorrelationUid: stringPtr(get(lv, "auditID"))}

			// Determine activity/type/status/severity
			activityId, activityName, typeUID, typeName := classifyAPIActivity(get(lv, "verb"))
			status := stringPtr("unknown")
			statusId := int32(0)
			severity := stringPtr("informational")
			severityId := int32(1)
			if code := tangenthelpers.GetInt64(lv, "responseStatus.code"); code != nil {
				if *code < 400 {
					*status = "success"
					statusId = 1
				} else {
					*status = "failure"
					statusId = 2
					*severity = "medium"
					severityId = 3
				}
			}

			// Build OCSF APIActivity
			out := ocsf.APIActivity{
				ActivityId:     activityId,
				ActivityName:   &activityName,
				Actor:          act,
				Api:            api,
				CategoryName:   stringPtr("Application Activity"),
				CategoryUid:    6,
				ClassName:      stringPtr("API Activity"),
				ClassUid:       6003,
				Metadata:       md,
				Resources:      resources,
				Severity:       severity,
				SeverityId:     severityId,
				SrcEndpoint:    se,
				Status:         status,
				StatusId:       &statusId,
				Time:           stage.UnixMilli(),
				TypeName:       &typeName,
				TypeUid:        int64(typeUID),
				TimezoneOffset: int32Ptr(0),
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

func get(lv log.Logview, path string) string {
	if v := tangenthelpers.GetString(lv, path); v != nil {
		return *v
	}
	return ""
}

func init() {
	Wire()
}

func main() {}

// classifyAPIActivity maps a verb to OCSF activity and type ids/names
func classifyAPIActivity(verb string) (int32, string, int, string) {
	v := verb
	// normalize to lower-case without allocating excessively
	// small set of cases; compare case-insensitively
	switch {
	case hasAnyPrefixFold(v, "create"): // create
		return 1, "create", 600301, "API Activity: Create"
	case hasAnyPrefixFold(v, "get", "list", "watch", "read"): // read
		return 2, "read", 600302, "API Activity: Read"
	case hasAnyPrefixFold(v, "update", "patch", "modify", "set"): // update
		return 3, "update", 600303, "API Activity: Update"
	case hasAnyPrefixFold(v, "delete", "remove"): // delete
		return 4, "delete", 600304, "API Activity: Delete"
	default:
		return 0, "unknown", 600300, "API Activity: Unknown"
	}
}

func hasAnyPrefixFold(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) {
			// case-insensitive compare without allocation
			match := true
			for i := 0; i < len(p); i++ {
				cs := s[i]
				cp := p[i]
				if cs >= 'A' && cs <= 'Z' {
					cs = cs - 'A' + 'a'
				}
				if cp >= 'A' && cp <= 'Z' {
					cp = cp - 'A' + 'a'
				}
				if cs != cp {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func int32Ptr(i int32) *int32    { return &i }
func stringPtr(s string) *string { return &s }
