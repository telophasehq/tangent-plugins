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

type ghAccount struct {
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	TypeId int    `json:"type_id,omitempty"`
	Uid    string `json:"uid,omitempty"`
}

type ghUser struct {
	Account   *ghAccount `json:"account,omitempty"`
	EmailAddr *string    `json:"email_addr,omitempty"`
	Name      *string    `json:"name,omitempty"`
	Type      *string    `json:"type,omitempty"`
	TypeId    *int       `json:"type_id,omitempty"`
	Uid       *string    `json:"uid,omitempty"`
}

type ghActor struct {
	User ghUser `json:"user"`
}

type ghAPI struct {
	Operation string `json:"operation"`
}

type ghHttpReq struct {
	UserAgent string `json:"user_agent"`
}

type ghProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type ghMetadata struct {
	EventCode string    `json:"event_code"`
	Product   ghProduct `json:"product"`
	Profiles  []string  `json:"profiles"`
	Uid       string    `json:"uid"`
	Version   string    `json:"version"`
}

type ghLocation struct {
	Country string `json:"country"`
}

type ghSrcEndpoint struct {
	Location ghLocation `json:"location"`
	Ip       string     `json:"ip"`
}

type ghObservable struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	TypeId int    `json:"type_id"`
	Value  string `json:"value"`
}

type ghResource struct {
	Name string `json:"name"`
	Uid  string `json:"uid"`
}

type ghUnmapped struct {
	ExternalId            string `json:"external_id"`
	TransportProtocolName string `json:"transport_protocol_name"`
	BusinessId            int    `json:"business_id"`
	User                  string `json:"user"`
	UserId                int    `json:"user_id"`
	RepositoryPublic      bool   `json:"repository_public"`
}

type ghOutput struct {
	ActivityId   int            `json:"activity_id"`
	ActivityName string         `json:"activity_name"`
	Actor        ghActor        `json:"actor"`
	Api          ghAPI          `json:"api"`
	CategoryName string         `json:"category_name"`
	CategoryUid  int            `json:"category_uid"`
	ClassName    string         `json:"class_name"`
	ClassUid     int            `json:"class_uid"`
	HttpRequest  ghHttpReq      `json:"http_request"`
	Metadata     ghMetadata     `json:"metadata"`
	Observables  []ghObservable `json:"observables"`
	Resources    []ghResource   `json:"resources"`
	Severity     string         `json:"severity"`
	SeverityId   int            `json:"severity_id"`
	SrcEndpoint  ghSrcEndpoint  `json:"src_endpoint"`
	Time         int64          `json:"time"`
	TimeDT       string         `json:"time_dt"`
	TypeName     string         `json:"type_name"`
	TypeUid      int            `json:"type_uid"`
	Unmapped     ghUnmapped     `json:"unmapped"`
}

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
			t := time.UnixMilli(ts).UTC()

			// Actor
			actorName := tangenthelpers.GetString(lv, "actor")
			actorId := tangenthelpers.GetInt64(lv, "actor_id")
			email := tangenthelpers.GetString(lv, "external_identity_nameid")
			org := tangenthelpers.GetString(lv, "org")
			orgId := tangenthelpers.GetInt64(lv, "org_id")

			acc := &ghAccount{}
			if org != nil {
				acc.Name = *org
			}
			acc.Type = "Other"
			acc.TypeId = 99
			if orgId != nil {
				acc.Uid = strconv.FormatInt(*orgId, 10)
			}
			u := ghUser{Account: acc, EmailAddr: email, Name: actorName}
			utype := 0
			u.TypeId = &utype
			utypeStr := "Unknown"
			u.Type = &utypeStr
			if actorId != nil {
				id := strconv.FormatInt(*actorId, 10)
				u.Uid = &id
			}
			actor := ghActor{User: u}

			// API
			op := ""
			if v := tangenthelpers.GetString(lv, "action"); v != nil {
				op = *v
			}
			api := ghAPI{Operation: op}

			// HTTP
			httpReq := ghHttpReq{}
			if v := tangenthelpers.GetString(lv, "user_agent"); v != nil {
				httpReq.UserAgent = *v
			}

			// Metadata
			md := ghMetadata{
				EventCode: op,
				Product:   ghProduct{Name: "GitHub Audit Log", VendorName: "GitHub"},
				Profiles:  []string{"datetime"},
				Version:   "1.3.0",
			}
			if v := tangenthelpers.GetString(lv, "_document_id"); v != nil {
				md.Uid = *v
			}

			// Source endpoint
			src := ghSrcEndpoint{}
			if v := tangenthelpers.GetString(lv, "actor_ip"); v != nil {
				src.Ip = *v
			}
			if v := tangenthelpers.GetString(lv, "actor_location.country_code"); v != nil {
				src.Location.Country = *v
			}

			// Observables
			var observables []ghObservable
			if src.Ip != "" {
				observables = append(observables, ghObservable{Name: "src_endpoint.ip", Type: "IP Address", TypeId: 2, Value: src.Ip})
			}
			if httpReq.UserAgent != "" {
				observables = append(observables, ghObservable{Name: "http_request.user_agent", Type: "HTTP User-Agent", TypeId: 16, Value: httpReq.UserAgent})
			}
			if actorName != nil {
				observables = append(observables, ghObservable{Name: "actor.user.name", Type: "User Name", TypeId: 4, Value: *actorName})
			}

			// Resources
			var resources []ghResource
			if v := tangenthelpers.GetString(lv, "repository"); v != nil {
				r := ghResource{Name: *v}
				if id := tangenthelpers.GetInt64(lv, "repository_id"); id != nil {
					r.Uid = strconv.FormatInt(*id, 10)
				}
				resources = append(resources, r)
			}

			// Unmapped
			unm := ghUnmapped{}
			if v := tangenthelpers.GetString(lv, "external_id"); v != nil {
				unm.ExternalId = *v
			}
			if v := tangenthelpers.GetString(lv, "transport_protocol_name"); v != nil {
				unm.TransportProtocolName = *v
			}
			if v := tangenthelpers.GetInt64(lv, "business_id"); v != nil {
				unm.BusinessId = int(*v)
			}
			if v := tangenthelpers.GetString(lv, "user"); v != nil {
				unm.User = *v
			}
			if v := tangenthelpers.GetInt64(lv, "user_id"); v != nil {
				unm.UserId = int(*v)
			}
			if ok, b := getBool(lv, "repository_public"); ok {
				unm.RepositoryPublic = b
			}

			out := ghOutput{
				ActivityId:   99,
				ActivityName: "Other",
				Actor:        actor,
				Api:          api,
				CategoryName: "Application Activity",
				CategoryUid:  6,
				ClassName:    "API Activity",
				ClassUid:     6003,
				HttpRequest:  httpReq,
				Metadata:     md,
				Observables:  observables,
				Resources:    resources,
				Severity:     "Informational",
				SeverityId:   1,
				SrcEndpoint:  src,
				Time:         ts,
				TimeDT:       t.Truncate(time.Second).Format("2006-01-02T15:04:05.000Z"),
				TypeName:     "API Activity: Other",
				TypeUid:      600399,
				Unmapped:     unm,
			}

			if err := json.NewEncoder(buf).Encode(out); err != nil {
				res.SetErr(err.Error())
				return
			}
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
