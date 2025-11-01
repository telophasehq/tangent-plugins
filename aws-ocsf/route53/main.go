package main

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"

	"route53/internal/tangent/logs/log"
	"route53/internal/tangent/logs/mapper"
	"route53/tangenthelpers"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// MappingSpec:
// version                  -> metadata.product.version (required)
// account_id               -> cloud.account.uid       (required)
// region                   -> cloud.region            (required)
// vpc_id                   -> src_endpoint.vpc_uid    (optional; default "")
// query_timestamp          -> time (epoch ms), time_dt (RFC3339 with -04:00)
// query_name               -> query.hostname
// query_type               -> query.type
// query_class              -> query.class
// rcode                    -> rcode/rcode_id (maps "NOERROR"->"NoError"/0)
// answers[].{Type,Rdata,Class} -> answers[].{type,rdata,class}
// srcaddr                  -> src_endpoint.ip
// srcport                  -> src_endpoint.port
// transport                -> connection_info.protocol_name
// srcids.resolver_endpoint -> dst_endpoint.instance_uid
// srcids.resolver_network_interface -> dst_endpoint.interface_uid
// firewall_rule_group_id   -> firewall_rule.uid
// firewall_rule_action     -> disposition (e.g., ALERT -> Alert)
// Constants:
// action/action_id = Allowed/1, activity_name/id = Traffic/6
// category/class fixed to Network Activity / DNS Activity (uids 4/4003)
// metadata.product.{name,vendor_name,feature.name} fixed to Route 53/AWS/Resolver Query Logs
// metadata.profiles [cloud, security_control, datetime]
// severity/severity_id = Informational/1
// type_name/type_uid = DNS Activity: Traffic / 400306

type route53Answer struct {
	Class string `json:"class"`
	RData string `json:"rdata"`
	Type  string `json:"type"`
}

type route53Cloud struct {
	Account struct {
		UID string `json:"uid"`
	} `json:"account"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
}

type route53ConnInfo struct {
	Direction   string `json:"direction"`
	DirectionID int    `json:"direction_id"`
	Protocol    string `json:"protocol_name"`
}

type route53Endpoint struct {
	IP           string `json:"ip,omitempty"`
	Port         int    `json:"port,omitempty"`
	VPCUID       string `json:"vpc_uid,omitempty"`
	InstanceUID  string `json:"instance_uid,omitempty"`
	InterfaceUID string `json:"interface_uid,omitempty"`
}

type route53FirewallRule struct {
	UID string `json:"uid"`
}

type route53Product struct {
	Feature struct {
		Name string `json:"name"`
	} `json:"feature"`
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

type route53Metadata struct {
	Product  route53Product `json:"product"`
	Profiles []string       `json:"profiles"`
	Version  string         `json:"version"`
}

type route53Observable struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	TypeID int    `json:"type_id"`
	Value  string `json:"value"`
}

type route53Query struct {
	Class    string `json:"class"`
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
}

type route53Unmapped struct {
	FirewallDomainListID string `json:"firewall_domain_list_id"`
}

type route53Output struct {
	Action       string              `json:"action"`
	ActionID     int                 `json:"action_id"`
	ActivityID   int                 `json:"activity_id"`
	ActivityName string              `json:"activity_name"`
	Answers      []route53Answer     `json:"answers"`
	CategoryName string              `json:"category_name"`
	CategoryUID  int                 `json:"category_uid"`
	ClassName    string              `json:"class_name"`
	ClassUID     int                 `json:"class_uid"`
	Cloud        route53Cloud        `json:"cloud"`
	Connection   route53ConnInfo     `json:"connection_info"`
	Disposition  string              `json:"disposition"`
	DstEndpoint  route53Endpoint     `json:"dst_endpoint"`
	FirewallRule route53FirewallRule `json:"firewall_rule"`
	Metadata     route53Metadata     `json:"metadata"`
	Observables  []route53Observable `json:"observables"`
	Query        route53Query        `json:"query"`
	RCode        string              `json:"rcode"`
	RCodeID      int                 `json:"rcode_id"`
	Severity     string              `json:"severity"`
	SeverityID   int                 `json:"severity_id"`
	SrcEndpoint  route53Endpoint     `json:"src_endpoint"`
	Time         int64               `json:"time"`
	TimeDT       string              `json:"time_dt"`
	TypeName     string              `json:"type_name"`
	TypeUID      int                 `json:"type_uid"`
	Unmapped     route53Unmapped     `json:"unmapped"`
}

func Wire() {
	// Metadata is for naming and versioning your plugin.
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "aws-route53 → ocsf.dns_activity",
			Version: "0.1.0",
		}
	}

	// Probe: require Route53 query fields
	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("query_name"),
					mapper.PredHas("query_type"),
					mapper.PredHas("query_class"),
				}),
				None: cm.ToList([]mapper.Pred{}),
			},
		})
	}

	// ProcessLogs takes a batch of logs, transforms, and outputs bytes.
	mapper.Exports.ProcessLogs = func(input cm.List[log.Logview]) (res cm.Result[cm.List[uint8], cm.List[uint8], string]) {
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		// Copy out the slice so we own the backing array.
		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			lv := log.Logview(items[idx])

			// OCSF v1.5 DNSActivity
			const classUID int32 = 4003
			const categoryUID int32 = 4
			activityID := int32(6) // Traffic
			severityID := int32(1)
			typeUID := int64(classUID)*100 + int64(activityID)

			// time
			var timeMs int64
			if v := tangenthelpers.GetString(lv, "query_timestamp"); v != nil {
				if t, err := time.Parse(time.RFC3339, *v); err == nil {
					timeMs = t.UnixMilli()
				}
			}

			// endpoints
			var src *ocsf.NetworkEndpoint
			if ip := tangenthelpers.GetString(lv, "srcaddr"); ip != nil {
				src = &ocsf.NetworkEndpoint{Ip: ip}
				if p := tangenthelpers.GetString(lv, "srcport"); p != nil {
					if n, err := strconv.Atoi(*p); err == nil {
						pn := int32(n)
						src.Port = &pn
					}
				}
				if v := tangenthelpers.GetString(lv, "vpc_id"); v != nil {
					src.VpcUid = v
				}
			}
			var dst *ocsf.NetworkEndpoint
			{
				dst = &ocsf.NetworkEndpoint{}
				if v := tangenthelpers.GetString(lv, "srcids.resolver_endpoint"); v != nil {
					dst.InstanceUid = v
				}
				if v := tangenthelpers.GetString(lv, "srcids.resolver_network_interface"); v != nil {
					dst.InterfaceUid = v
				}
				if dst.InstanceUid == nil && dst.InterfaceUid == nil {
					dst = nil
				}
			}

			// connection info
			var conn *ocsf.NetworkConnectionInformation
			if tr := tangenthelpers.GetString(lv, "transport"); tr != nil {
				name := strings.ToLower(*tr)
				conn = &ocsf.NetworkConnectionInformation{ProtocolName: &name}
			}

			// query
			q := &ocsf.DNSQuery{}
			if v := tangenthelpers.GetString(lv, "query_name"); v != nil {
				q.Hostname = *v
			}
			if v := tangenthelpers.GetString(lv, "query_type"); v != nil {
				q.Type = v
			}
			if v := tangenthelpers.GetString(lv, "query_class"); v != nil {
				q.Class = v
			}

			// answers (first only)
			var answers []ocsf.DNSAnswer
			if n := tangenthelpers.Len(lv, "answers"); n != nil && *n > 0 {
				if v := tangenthelpers.GetString(lv, "answers[0].Rdata"); v != nil {
					answers = append(answers, ocsf.DNSAnswer{Rdata: *v})
				}
			}

			// rcode
			var rcode *string
			var rcodeId *int32
			if v := tangenthelpers.GetString(lv, "rcode"); v != nil {
				rcode = v
				id := int32(99)
				switch *v {
				case "NOERROR":
					id = 0
				case "FormError":
					id = 1
				case "ServFail", "ServError":
					id = 2
				case "NXDomain":
					id = 3
				case "NotImp":
					id = 4
				case "Refused":
					id = 5
				}
				rcodeId = &id
			}

			// metadata
			prod := "Route 53"
			vendor := "AWS"
			md := ocsf.Metadata{Version: "1.5.0", Product: ocsf.Product{Name: &prod, VendorName: &vendor}}

			out := ocsf.DNSActivity{
				ActivityId:     activityID,
				CategoryUid:    categoryUID,
				ClassUid:       classUID,
				SeverityId:     severityID,
				TypeUid:        typeUID,
				Time:           timeMs,
				Metadata:       md,
				SrcEndpoint:    src,
				DstEndpoint:    dst,
				ConnectionInfo: conn,
				Query:          q,
				Answers:        answers,
				Rcode:          rcode,
				RcodeId:        rcodeId,
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

// mapRCode maps common DNS rcode strings to OCSF name/id pairs.
// Minimal set for fixtures; default to passthrough name with id 99.
func mapRCode(s string) (string, int) {
	switch s {
	case "NOERROR":
		return "NoError", 0
	case "FormError":
		return "FormError", 1
	case "ServFail", "ServError":
		return "ServFail", 2
	case "NXDomain":
		return "NXDomain", 3
	case "NotImp":
		return "NotImp", 4
	case "Refused":
		return "Refused", 5
	default:
		return s, 99
	}
}

func init() {
	Wire()
}

func main() {}
