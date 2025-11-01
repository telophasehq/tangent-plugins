package main

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"github_audit_api_activity/internal/tangent/logs/log"
	"github_audit_api_activity/internal/tangent/logs/mapper"
	"github_audit_api_activity/tangenthelpers"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// MappingSpec:
// actor -> actor.user fields from raw (actor, actor_id, external_identity_nameid)
// api.operation <- action
// http_request.user_agent <- user_agent
// metadata.event_code <- action; metadata.product.{name,vendor_name}; metadata.profiles ["datetime"]; metadata.uid <- _document_id; metadata.version "1.3.0"
// src_endpoint.ip <- actor_ip; src_endpoint.location.country <- actor_location.country_code
// resources[0].name <- repository; resources[0].uid <- repository_id
// time <- @timestamp; time_dt RFC3339 with Z
// activity fixed to Other (99)
// category/class fixed to Application Activity/API Activity (uids 6/6003)
// severity Informational/1
// unmapped carries passthroughs: external_id, transport_protocol_name, business_id, user, user_id, repository_public

// legacy structs removed; use OCSF v1.5 typed model

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "github-audit → ocsf.api_activity",
			Version: "0.1.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("action"),
					mapper.PredHas("@timestamp"),
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

			// Time
			var ts int64
			if v := tangenthelpers.GetInt64(lv, "@timestamp"); v != nil {
				ts = *v
			}
			_ = time.UnixMilli(ts).UTC()

			// Actor (OCSF)
			var actor ocsf.Actor
			var user ocsf.User
			if v := tangenthelpers.GetString(lv, "actor"); v != nil {
				user.Name = v
			}
			if v := tangenthelpers.GetString(lv, "external_identity_nameid"); v != nil {
				user.EmailAddr = v
			}
			if id := tangenthelpers.GetInt64(lv, "actor_id"); id != nil {
				s := strconv.FormatInt(*id, 10)
				user.Uid = &s
			}
			// account from org
			if org := tangenthelpers.GetString(lv, "org"); org != nil {
				acc := ocsf.Account{Name: org, Type: stringPtr("Other"), TypeId: int32Ptr(99)}
				if orgId := tangenthelpers.GetInt64(lv, "org_id"); orgId != nil {
					uid := strconv.FormatInt(*orgId, 10)
					acc.Uid = &uid
				}
				user.Account = &acc
			}
			actor.User = &user

			// API
			op := ""
			if v := tangenthelpers.GetString(lv, "action"); v != nil {
				op = *v
			}
			api := ocsf.API{Operation: op}

			// Source endpoint
			var src ocsf.NetworkEndpoint
			if v := tangenthelpers.GetString(lv, "actor_ip"); v != nil {
				src.Ip = v
			}
			if v := tangenthelpers.GetString(lv, "actor_location.country_code"); v != nil {
				src.Location = &ocsf.GeoLocation{Country: v}
			}

			// Metadata
			prodName := "GitHub Audit Log"
			vendor := "GitHub"
			md := ocsf.Metadata{Version: "1.5.0", Product: ocsf.Product{Name: &prodName, VendorName: &vendor}, EventCode: &op}
			if v := tangenthelpers.GetString(lv, "_document_id"); v != nil {
				md.Uid = v
			}

			// Resources
			var resources []ocsf.ResourceDetails
			if v := tangenthelpers.GetString(lv, "repository"); v != nil {
				var uid *string
				if id := tangenthelpers.GetInt64(lv, "repository_id"); id != nil {
					s := strconv.FormatInt(*id, 10)
					uid = &s
				}
				resources = append(resources, ocsf.ResourceDetails{Name: v, Uid: uid})
			}

			// Build OCSF object
			activityId := int32(99)
			activityName := "Other"
			classUid := int32(6003)
			categoryUid := int32(6)
			typeUid := int64(classUid)*100 + int64(activityId)
			typeName := "API Activity: Other"
			sev := "informational"
			severityId := int32(1)
			out := ocsf.APIActivity{
				ActivityId:     activityId,
				ActivityName:   &activityName,
				Actor:          actor,
				Api:            api,
				CategoryName:   stringPtr("Application Activity"),
				CategoryUid:    categoryUid,
				ClassName:      stringPtr("API Activity"),
				ClassUid:       classUid,
				Metadata:       md,
				Resources:      resources,
				Severity:       &sev,
				SeverityId:     severityId,
				SrcEndpoint:    src,
				Time:           ts,
				TypeName:       &typeName,
				TypeUid:        typeUid,
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

func init() {
	Wire()
}

func main() {}

func int32Ptr(i int32) *int32    { return &i }
func stringPtr(s string) *string { return &s }

// Helpers
func getBool(lv log.Logview, path string) (bool, bool) {
	if s := tangenthelpers.GetString(lv, path); s != nil {
		if *s == "true" {
			return true, true
		}
		if *s == "false" {
			return true, false
		}
	}
	return false, false
}
