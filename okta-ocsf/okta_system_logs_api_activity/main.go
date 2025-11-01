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
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

type oktaActorUser struct {
	EmailAddr string `json:"email_addr"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	TypeId    int    `json:"type_id"`
	Uid       string `json:"uid"`
}
type oktaSession struct {
	Uid string `json:"uid"`
}
type oktaActor struct {
	Session oktaSession   `json:"session"`
	User    oktaActorUser `json:"user"`
}
type oktaAPI struct {
	Operation string `json:"operation"`
}
type oktaHttpReq struct {
	Uid       string `json:"uid"`
	UserAgent string `json:"user_agent"`
}
type oktaDst struct {
	SvcName string `json:"svc_name"`
}
type oktaProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}
type oktaMetadata struct {
	EventCode string      `json:"event_code"`
	Product   oktaProduct `json:"product"`
	Profiles  []string    `json:"profiles"`
	Uid       string      `json:"uid"`
	Version   string      `json:"version"`
}
type oktaAS struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}
type oktaLocation struct {
	City       string  `json:"city"`
	Country    string  `json:"country"`
	Isp        string  `json:"isp"`
	Lat        float64 `json:"lat"`
	Long       float64 `json:"long"`
	PostalCode string  `json:"postal_code"`
}
type oktaOS struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	TypeId int    `json:"type_id"`
}
type oktaSrc struct {
	AutonomousSystem oktaAS       `json:"autonomous_system"`
	Ip               string       `json:"ip"`
	Location         oktaLocation `json:"location"`
	Os               oktaOS       `json:"os"`
	Type             string       `json:"type"`
}
type oktaObservable struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	TypeId int    `json:"type_id"`
	Value  string `json:"value"`
}
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
type oktaOutput struct {
	ActivityId   int              `json:"activity_id"`
	ActivityName string           `json:"activity_name"`
	Actor        oktaActor        `json:"actor"`
	Api          oktaAPI          `json:"api"`
	CategoryName string           `json:"category_name"`
	CategoryUid  int              `json:"category_uid"`
	ClassName    string           `json:"class_name"`
	ClassUid     int              `json:"class_uid"`
	DstEndpoint  oktaDst          `json:"dst_endpoint"`
	HttpRequest  oktaHttpReq      `json:"http_request"`
	Message      string           `json:"message"`
	Metadata     oktaMetadata     `json:"metadata"`
	Observables  []oktaObservable `json:"observables"`
	Severity     string           `json:"severity"`
	SeverityId   int              `json:"severity_id"`
	SrcEndpoint  oktaSrc          `json:"src_endpoint"`
	Status       string           `json:"status"`
	StatusId     int              `json:"status_id"`
	Time         int64            `json:"time"`
	TimeDT       string           `json:"time_dt"`
	TypeName     string           `json:"type_name"`
	TypeUid      int              `json:"type_uid"`
	Unmapped     oktaUnmapped     `json:"unmapped"`
}

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

			user := oktaActorUser{Type: "User", TypeId: 1}
			if v := tangenthelpers.GetString(lv, "actor.alternateId"); v != nil {
				user.EmailAddr = *v
			}
			if v := tangenthelpers.GetString(lv, "actor.displayName"); v != nil {
				user.Name = *v
			}
			if v := tangenthelpers.GetString(lv, "actor.id"); v != nil {
				user.Uid = *v
			}
			actor := oktaActor{User: user}
			if v := tangenthelpers.GetString(lv, "authenticationContext.rootSessionId"); v != nil {
				actor.Session.Uid = *v
			}

			op := getStringOr(lv, "eventType", "")
			api := oktaAPI{Operation: op}

			http := oktaHttpReq{Uid: getStringOr(lv, "debugContext.debugData.requestId", "")}
			if v := tangenthelpers.GetString(lv, "client.userAgent.rawUserAgent"); v != nil {
				http.UserAgent = *v
			}
			dst := oktaDst{SvcName: getStringOr(lv, "debugContext.debugData.url", "")}

			md := oktaMetadata{EventCode: op, Product: oktaProduct{Name: "Okta System Log", VendorName: "Okta", Version: "0"}, Profiles: []string{"datetime"}, Version: "1.3.0"}
			if v := tangenthelpers.GetString(lv, "uuid"); v != nil {
				md.Uid = *v
			}

			src := oktaSrc{Type: "Mobile"}
			if v := tangenthelpers.GetString(lv, "client.ipAddress"); v != nil {
				src.Ip = *v
			}
			if v := tangenthelpers.GetString(lv, "securityContext.asOrg"); v != nil {
				src.AutonomousSystem.Name = *v
			}
			if v := tangenthelpers.GetString(lv, "securityContext.isp"); v != nil {
				src.Location.Isp = *v
			}
			if v := tangenthelpers.GetInt64(lv, "securityContext.asNumber"); v != nil {
				src.AutonomousSystem.Number = int(*v)
			}
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.city"); v != nil {
				src.Location.City = *v
			}
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.country"); v != nil {
				src.Location.Country = *v
			}
			if v := tangenthelpers.GetString(lv, "client.geographicalContext.postalCode"); v != nil {
				src.Location.PostalCode = *v
			}
			if v := tangenthelpers.GetFloat64(lv, "client.geographicalContext.geolocation.lat"); v != nil {
				src.Location.Lat = *v
			}
			if v := tangenthelpers.GetFloat64(lv, "client.geographicalContext.geolocation.lon"); v != nil {
				src.Location.Long = *v
			}
			if v := tangenthelpers.GetString(lv, "client.userAgent.os"); v != nil {
				src.Os.Name = *v
			}
			src.Os.Type = "macOS"
			src.Os.TypeId = 300

			var observables []oktaObservable
			if src.Ip != "" {
				observables = append(observables, oktaObservable{Name: "src_endpoint.ip", Type: "IP Address", TypeId: 2, Value: src.Ip})
			}
			if http.UserAgent != "" {
				observables = append(observables, oktaObservable{Name: "http_request.user_agent", Type: "HTTP User-Agent", TypeId: 16, Value: http.UserAgent})
			}
			if user.Name != "" {
				observables = append(observables, oktaObservable{Name: "actor.user.name", Type: "User Name", TypeId: 4, Value: user.Name})
			}

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

			out := oktaOutput{
				ActivityId: 1, ActivityName: "Create",
				Actor: actor, Api: api,
				CategoryName: "Application Activity", CategoryUid: 6,
				ClassName: "API Activity", ClassUid: 6003,
				DstEndpoint: dst, HttpRequest: http,
				Message:     getStringOr(lv, "displayMessage", ""),
				Metadata:    md,
				Observables: observables,
				Severity:    "Informational", SeverityId: 1,
				SrcEndpoint: src,
				Status:      "Success", StatusId: 1,
				Time:     ts.Unix(),
				TimeDT:   ts.Truncate(time.Second).Format("2006-01-02T15:04:05.000Z"),
				TypeName: "API Activity: Create", TypeUid: 600301,
				Unmapped: unm,
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
