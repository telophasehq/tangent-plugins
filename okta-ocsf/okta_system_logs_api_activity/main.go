package main

import (
	"bytes"
	"strconv"
	"sync"
	"time"

	"okta_system_logs_api_activity/internal/tangent/logs/log"
	"okta_system_logs_api_activity/internal/tangent/logs/mapper"
	"okta_system_logs_api_activity/tangenthelpers"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

type oktaAuthCtx struct {
	AuthenticationStep int    `json:"authenticationStep"`
	RootSessionId      string `json:"rootSessionId"`
	ExternalSessionId  string `json:"externalSessionId,omitempty"`
}
type oktaSecCtx struct {
	AsNumber int    `json:"asNumber,omitempty"`
	AsOrg    string `json:"asOrg,omitempty"`
	Isp      string `json:"isp,omitempty"`
	IsProxy  bool   `json:"isProxy"`
}
type oktaDebugData struct {
	RequestId  string `json:"requestId,omitempty"`
	RequestUri string `json:"requestUri"`
	Url        string `json:"url,omitempty"`
}
type oktaDebugCtx struct {
	DebugData oktaDebugData `json:"debugData"`
}
type oktaTxn struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}
type oktaGeoLoc struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}
type oktaGeoCtx struct {
	City        string     `json:"city"`
	State       string     `json:"state"`
	Country     string     `json:"country"`
	PostalCode  int        `json:"postalCode"`
	Geolocation oktaGeoLoc `json:"geolocation"`
}
type oktaIpChainEntry struct {
	Ip                  string     `json:"ip"`
	GeographicalContext oktaGeoCtx `json:"geographicalContext"`
	Version             string     `json:"version"`
	Source              *string    `json:"source"`
}
type oktaRequest struct {
	IpChain []oktaIpChainEntry `json:"ipChain"`
}
type oktaUnmapped struct {
	AuthenticationContext oktaAuthCtx  `json:"authenticationContext"`
	SecurityContext       oktaSecCtx   `json:"securityContext"`
	DebugContext          oktaDebugCtx `json:"debugContext"`
	Transaction           oktaTxn      `json:"transaction"`
	Request               oktaRequest  `json:"request"`
}

// legacy output replaced by OCSF v1.5 APIActivity

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "okta-system-log → ocsf.api_activity",
			Version: "0.1.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{{
			Any:  cm.ToList([]mapper.Pred{}),
			All:  cm.ToList([]mapper.Pred{mapper.PredHas("eventType"), mapper.PredHas("published")}),
			None: cm.ToList([]mapper.Pred{}),
		}})
	}

	mapper.Exports.ProcessLogs = func(input cm.List[log.Logview]) (res cm.Result[cm.List[uint8], cm.List[uint8], string]) {
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			lv := log.Logview(items[idx])

			var ts time.Time
			if v := tangenthelpers.GetString(lv, "published"); v != nil {
				if t, err := time.Parse(time.RFC3339Nano, *v); err == nil {
					ts = t.UTC()
				}
			}

			// Actor
			var actor ocsf.Actor
			var user ocsf.User
			user.Type = stringPtr("User")
			user.TypeId = int32Ptr(1)
			if v := tangenthelpers.GetString(lv, "actor.alternateId"); v != nil {
				user.EmailAddr = v
			}
			if v := tangenthelpers.GetString(lv, "actor.displayName"); v != nil {
				user.Name = v
			}
			if v := tangenthelpers.GetString(lv, "actor.id"); v != nil {
				user.Uid = v
			}
			actor.User = &user
			if v := tangenthelpers.GetString(lv, "authenticationContext.rootSessionId"); v != nil {
				actor.Session = &ocsf.Session{Uid: v}
			}

			op := getStringOr(lv, "eventType", "")
			api := ocsf.API{Operation: op}

			// Destination/service context not required in 1.5 minimal

			prod := "Okta System Log"
			vendor := "Okta"
			md := ocsf.Metadata{Version: "1.5.0", Product: ocsf.Product{Name: &prod, VendorName: &vendor}, EventCode: &op}
			if v := tangenthelpers.GetString(lv, "uuid"); v != nil {
				md.Uid = v
			}

			var src ocsf.NetworkEndpoint
			if v := tangenthelpers.GetString(lv, "client.ipAddress"); v != nil {
				src.Ip = v
			}
			var loc ocsf.GeoLocation
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.city"); v != nil {
				loc.City = v
			}
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.country"); v != nil {
				loc.Country = v
			}
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.postalCode"); v != nil {
				loc.PostalCode = v
			}
			if v := tangenthelpers.GetFloat64(lv, "client.geographicalContext.geolocation.lat"); v != nil {
				loc.Lat = v
			}
			if v := tangenthelpers.GetFloat64(lv, "client.geographicalContext.geolocation.lon"); v != nil {
				loc.Long = v
			}
			// set only if any present
			if loc.City != nil || loc.Country != nil || loc.PostalCode != nil || loc.Lat != nil || loc.Long != nil {
				src.Location = &loc
			}

			// Observables omitted in minimal 1.5 output

			unm := oktaUnmapped{}
			if v := tangenthelpers.GetInt64(lv, "authenticationContext.authenticationStep"); v != nil {
				unm.AuthenticationContext.AuthenticationStep = int(*v)
			}
			if v := tangenthelpers.GetString(lv, "authenticationContext.rootSessionId"); v != nil {
				unm.AuthenticationContext.RootSessionId = *v
			}
			// externalSessionId is present in raw but omitted in expected; skip

			// Only include isProxy (expected); omit asNumber/asOrg/isp
			if s := tangenthelpers.GetString(lv, "securityContext.isProxy"); s != nil {
				unm.SecurityContext.IsProxy = (*s == "true")
			}

			// Only include requestUri to match expected
			if v := tangenthelpers.GetString(lv, "debugContext.debugData.requestUri"); v != nil {
				unm.DebugContext.DebugData.RequestUri = *v
			}

			if v := tangenthelpers.GetString(lv, "transaction.type"); v != nil {
				unm.Transaction.Type = *v
			}
			if v := tangenthelpers.GetString(lv, "transaction.id"); v != nil {
				unm.Transaction.Id = *v
			}

			if n := tangenthelpers.Len(lv, "request.ipChain"); n != nil && *n > 0 {
				unm.Request.IpChain = make([]oktaIpChainEntry, 0, int(*n))
				for i := 0; i < int(*n); i++ {
					e := oktaIpChainEntry{}
					if v := tangenthelpers.GetString(lv, "request.ipChain["+strconv.Itoa(i)+"].ip"); v != nil {
						e.Ip = *v
					}
					if v := tangenthelpers.GetString(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.city"); v != nil {
						e.GeographicalContext.City = *v
					}
					if v := tangenthelpers.GetString(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.state"); v != nil {
						e.GeographicalContext.State = *v
					}
					if v := tangenthelpers.GetString(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.country"); v != nil {
						e.GeographicalContext.Country = *v
					}
					if v := tangenthelpers.GetInt64(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.postalCode"); v != nil {
						e.GeographicalContext.PostalCode = int(*v)
					}
					if v := tangenthelpers.GetFloat64(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.geolocation.lat"); v != nil {
						e.GeographicalContext.Geolocation.Lat = *v
					}
					if v := tangenthelpers.GetFloat64(lv, "request.ipChain["+strconv.Itoa(i)+"].geographicalContext.geolocation.lon"); v != nil {
						e.GeographicalContext.Geolocation.Lon = *v
					}
					if v := tangenthelpers.GetString(lv, "request.ipChain["+strconv.Itoa(i)+"].version"); v != nil {
						e.Version = *v
					}
					// include null source
					e.Source = nil
					unm.Request.IpChain = append(unm.Request.IpChain, e)
				}
			}

			// Activity classification
			activityId, activityName, typeUid, typeName := classifyAPIActivity(op)
			sev := "informational"
			severityId := int32(1)
			status := "success"
			statusId := int32(1)
			out := ocsf.APIActivity{
				ActivityId:     activityId,
				ActivityName:   &activityName,
				Actor:          actor,
				Api:            api,
				CategoryName:   stringPtr("Application Activity"),
				CategoryUid:    6,
				ClassName:      stringPtr("API Activity"),
				ClassUid:       6003,
				Message:        stringPtr(getStringOr(lv, "displayMessage", "")),
				Metadata:       md,
				Severity:       &sev,
				SeverityId:     severityId,
				SrcEndpoint:    src,
				Status:         &status,
				StatusId:       &statusId,
				Time:           ts.UnixMilli(),
				TypeName:       &typeName,
				TypeUid:        int64(typeUid),
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

func getStringOr(lv log.Logview, path, def string) string {
	if v := tangenthelpers.GetString(lv, path); v != nil {
		return *v
	}
	return def
}

func copyObject(lv log.Logview, path string) map[string]any {
	// This mapper runtime doesn't support dynamic object copies; return nil to avoid overhead.
	return nil
}

func init() {
	Wire()
}

func main() {}

func int32Ptr(i int32) *int32    { return &i }
func stringPtr(s string) *string { return &s }

func classifyAPIActivity(op string) (int32, string, int, string) {
	if containsFold(op, "create") {
		return 1, "create", 600301, "API Activity: Create"
	}
	if containsFold(op, "get") || containsFold(op, "list") || containsFold(op, "read") {
		return 2, "read", 600302, "API Activity: Read"
	}
	if containsFold(op, "update") || containsFold(op, "modify") || containsFold(op, "set") || containsFold(op, "patch") {
		return 3, "update", 600303, "API Activity: Update"
	}
	if containsFold(op, "delete") || containsFold(op, "remove") {
		return 4, "delete", 600304, "API Activity: Delete"
	}
	return 99, "other", 600399, "API Activity: Other"
}

func containsFold(s, sub string) bool {
	// simple case-insensitive substring search without allocation
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			cs := s[i+j]
			cp := sub[j]
			if cs >= 'A' && cs <= 'Z' {
				cs = cs - 'A' + 'a'
			}
			if cp >= 'A' && cp <= 'Z' {
				cp = cp - 'A' + 'a'
			}
			if cs != cp {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
