package main

import (
	"bytes"
	"sync"
	"time"

	"dns/internal/tangent/logs/log"
	"dns/internal/tangent/logs/mapper"
	"dns/tangenthelpers"

	"github.com/segmentio/encoding/json"
	"github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "zeek-dns → ocsf.dns_activity",
			Version: "0.1.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("uid"),
					mapper.PredEq(cm.Tuple[string, mapper.Scalar]{
						F0: "_path",
						F1: log.ScalarStr("dns"),
					}),
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

			rawWTS := tangenthelpers.GetString(lv, "_write_ts")
			var writeTimeMs int64
			if rawWTS != nil {
				if wts, err := time.Parse(time.RFC3339Nano, *rawWTS); err == nil {
					writeTimeMs = wts.UnixMilli()
				}
			}

			const classUID int32 = 4003 // dns_activity
			const categoryUID int32 = 4 // Network Activity
			activityID := dnsActivityIDFromLogview(lv)
			var severityID int32 = 1
			typeUID := int64(classUID)*100 + int64(activityID)

			var connInfo *v1_5_0.NetworkConnectionInformation
			if p := tangenthelpers.GetString(lv, "proto"); p != nil {
				_, protoName := protoToOCSF(*p)
				if protoName != "" {
					pn := protoName
					connInfo = &v1_5_0.NetworkConnectionInformation{ProtocolName: &pn}
				}
			}

			q := &v1_5_0.DNSQuery{}
			if h := tangenthelpers.GetString(lv, "query"); h != nil {
				q.Hostname = *h
			}
			if qtName := tangenthelpers.GetString(lv, "qtype_name"); qtName != nil {
				q.Type = qtName
			} else if qt := tangenthelpers.GetInt64(lv, "qtype"); qt != nil {
				s := dnsQTypeName(int(*qt))
				q.Type = &s
			}
			if qcName := tangenthelpers.GetString(lv, "qclass_name"); qcName != nil {
				q.Class = qcName
			}
			if trans := tangenthelpers.GetInt64(lv, "trans_id"); trans != nil {
				pu := int32(*trans)
				q.PacketUid = &pu
			}

			var answers []v1_5_0.DNSAnswer
			if ans, ok := tangenthelpers.GetStringList(lv, "answers"); ok {
				var ttls []int64
				if tt, okTT := tangenthelpers.GetInt64List(lv, "TTLs"); okTT {
					ttls = tt
				}
				for i := range ans {
					a := v1_5_0.DNSAnswer{Rdata: ans[i]}
					if i < len(ttls) {
						t := int32(ttls[i])
						a.Ttl = &t
					}
					if q.PacketUid != nil {
						a.PacketUid = q.PacketUid
					}
					if ids := dnsFlagIDsFromLogview(lv); len(ids) > 0 {
						a.FlagIds = ids
					}
					answers = append(answers, a)
				}
			}

			var rcodePtr *string
			var rcodeIdPtr *int32
			if rn := tangenthelpers.GetString(lv, "rcode_name"); rn != nil {
				rcodePtr = rn
			} else if r := tangenthelpers.GetInt64(lv, "rcode"); r != nil {
				s := dnsRcodeName(int(*r))
				rcodePtr = &s
			}
			if r := tangenthelpers.GetInt64(lv, "rcode"); r != nil {
				ri := int32(*r)
				rcodeIdPtr = &ri
			}

			ver := "1.5.0"
			product := "Zeek"
			vendor := "Zeek"
			md := v1_5_0.Metadata{
				Version: ver,
				Product: v1_5_0.Product{Name: &product, VendorName: &vendor},
			}
			if uid := tangenthelpers.GetString(lv, "uid"); uid != nil {
				md.Uid = uid
			}
			if path := tangenthelpers.GetString(lv, "_path"); path != nil {
				md.LogName = path
			}
			if writeTimeMs != 0 {
				md.LoggedTime = writeTimeMs
			}
			if system := tangenthelpers.GetString(lv, "_system_name"); system != nil {
				md.Loggers = []v1_5_0.Logger{{Name: system}}
			}

			var responseTime int64
			if rtt := tangenthelpers.GetFloat64(lv, "rtt"); rtt != nil {
				responseTime = int64(*rtt * 1000)
			}

			var statusId *int32
			if rej := tangenthelpers.GetBool(lv, "rejected"); rej != nil {
				if *rej {
					failed := int32(2)
					statusId = &failed
				} else {
					success := int32(1)
					statusId = &success
				}
			}

			unmapped := map[string]any{}
			if v := tangenthelpers.GetString(lv, "icann_host_subdomain"); v != nil {
				unmapped["icann_host_subdomain"] = *v
			}
			if v := tangenthelpers.GetString(lv, "icann_domain"); v != nil {
				unmapped["icann_domain"] = *v
			}
			if v := tangenthelpers.GetString(lv, "icann_tld"); v != nil {
				unmapped["icann_tld"] = *v
			}
			if v := tangenthelpers.GetBool(lv, "is_trusted_domain"); v != nil {
				unmapped["is_trusted_domain"] = *v
			}
			if v := tangenthelpers.GetInt64(lv, "qclass"); v != nil {
				unmapped["qclass"] = *v
			}
			if v := tangenthelpers.GetInt64(lv, "qtype"); v != nil {
				unmapped["qtype"] = *v
			}
			var unmappedPtr *string
			if len(unmapped) > 0 {
				if b, err := json.Marshal(unmapped); err == nil {
					s := string(b)
					unmappedPtr = &s
				}
			}

			var src, dst *v1_5_0.NetworkEndpoint
			if h := tangenthelpers.GetString(lv, "id.orig_h"); h != nil {
				var p int
				if pp := tangenthelpers.GetInt64(lv, "id.orig_p"); pp != nil {
					p = int(*pp)
				}
				src = toNetEndpoint(*h, p)
			}
			if h := tangenthelpers.GetString(lv, "id.resp_h"); h != nil {
				var p int
				if pp := tangenthelpers.GetInt64(lv, "id.resp_p"); pp != nil {
					p = int(*pp)
				}
				dst = toNetEndpoint(*h, p)
			}

			out := v1_5_0.DNSActivity{
				ActivityId:     activityID,
				CategoryUid:    categoryUID,
				ClassUid:       classUID,
				SeverityId:     severityID,
				StatusId:       statusId,
				TypeUid:        typeUID,
				Time:           writeTimeMs,
				StartTime:      writeTimeMs,
				Metadata:       md,
				SrcEndpoint:    src,
				DstEndpoint:    dst,
				ConnectionInfo: connInfo,
				Query:          q,
				Answers:        answers,
				Rcode:          rcodePtr,
				RcodeId:        rcodeIdPtr,
				ResponseTime:   responseTime,
				Unmapped:       unmappedPtr,
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

/* ---------------- helpers ---------------- */

func toNetEndpoint(ip string, port int) *v1_5_0.NetworkEndpoint {
	ep := &v1_5_0.NetworkEndpoint{}
	if ip != "" {
		ep.Ip = &ip
	}
	if port != 0 {
		p := int32(port)
		ep.Port = &p
	}
	return ep
}

// Simplified: return (num, name) for OCSF proto fields.
func protoToOCSF(p string) (int, string) {
	switch p {
	case "tcp":
		return 6, "tcp"
	case "udp":
		return 17, "udp"
	default:
		return 0, p
	}
}

func dnsFlagIDsFromLogview(v log.Logview) []int32 {
	var ids []int32
	if b := tangenthelpers.GetBool(v, "AA"); b != nil && *b {
		ids = append(ids, 1)
	}
	if b := tangenthelpers.GetBool(v, "TC"); b != nil && *b {
		ids = append(ids, 2)
	}
	if b := tangenthelpers.GetBool(v, "RD"); b != nil && *b {
		ids = append(ids, 3)
	}
	if b := tangenthelpers.GetBool(v, "RA"); b != nil && *b {
		ids = append(ids, 4)
	}
	return ids
}

func dnsActivityIDFromLogview(v log.Logview) int32 {
	hasQuery := tangenthelpers.GetString(v, "query") != nil && *tangenthelpers.GetString(v, "query") != ""
	hasRcodeName := tangenthelpers.GetString(v, "rcode_name") != nil && *tangenthelpers.GetString(v, "rcode_name") != ""
	hasRcode := tangenthelpers.GetInt64(v, "rcode") != nil && *tangenthelpers.GetInt64(v, "rcode") != 0
	answers, _ := tangenthelpers.GetStringList(v, "answers")
	hasResp := (len(answers) > 0) || hasRcodeName || hasRcode

	var activity int
	switch {
	case hasQuery && hasResp:
		activity = 6 // Traffic
	case hasQuery && !hasResp:
		activity = 1 // Query
	case !hasQuery && hasResp:
		activity = 2 // Response
	default:
		activity = 0 // Unknown
	}
	return int32(activity)
}

func dnsRcodeName(id int) string {
	switch id {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return "unknown"
	}
}

func dnsQTypeName(id int) string {
	switch id {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return "unknown"
	}
}
