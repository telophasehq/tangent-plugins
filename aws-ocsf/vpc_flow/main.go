package main

import (
	"bytes"
	"sync"
	"vpc_flow/internal/tangent/logs/log"
	"vpc_flow/internal/tangent/logs/mapper"
	"vpc_flow/tangenthelpers"

	"github.com/segmentio/encoding/json"

	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// MappingSpec:
// source.name          -> metadata.product (name=VPC Flow Logs, vendor_name=AWS) (required)
// start_time           -> start_time (optional; default 0)
// end_time             -> end_time (optional; default 0)
// end_time or start_time -> time (required; choose end_time when present)
// srcaddr              -> src_endpoint.ip (optional; default "")
// srcport              -> src_endpoint.port (optional; default 0)
// dstaddr              -> dst_endpoint.ip (optional; default "")
// dstport              -> dst_endpoint.port (optional; default 0)
// vpc_id               -> src_endpoint.vpc_uid (optional; default "")
// protocol_name        -> connection_info.protocol_name (falls back to protocol number mapping)
// protocol             -> connection_info.protocol_name (map: 6->tcp, 17->udp, else "")
// packets              -> traffic.packets (optional; default 0)
// bytes                -> traffic.bytes (optional; default 0)
// Constants:
// metadata.version = "1.5.0"; category_uid=4; class_uid=4001; severity_id=1; activity_id=2; type_uid=400102

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

type Endpoint struct {
	IP     string `json:"ip"`
	Port   int64  `json:"port,omitempty"`
	VPCUID string `json:"vpc_uid,omitempty"`
}

type ConnectionInfo struct {
	DirectionID  int64  `json:"direction_id"`
	ProtocolName string `json:"protocol_name"`
}

type Traffic struct {
	Bytes   int64 `json:"bytes"`
	Packets int64 `json:"packets"`
}

type NetworkActivity struct {
	Metadata       Metadata       `json:"metadata"`
	CategoryUID    int64          `json:"category_uid"`
	ClassUID       int64          `json:"class_uid"`
	SeverityID     int64          `json:"severity_id"`
	Time           int64          `json:"time"`
	StartTime      int64          `json:"start_time,omitempty"`
	EndTime        int64          `json:"end_time,omitempty"`
	SrcEndpoint    Endpoint       `json:"src_endpoint"`
	DstEndpoint    Endpoint       `json:"dst_endpoint"`
	ConnectionInfo ConnectionInfo `json:"connection_info"`
	Traffic        Traffic        `json:"traffic"`
	ActivityID     int64          `json:"activity_id"`
	TypeUID        int64          `json:"type_uid"`
}

func Wire() {
	// Metadata is for naming and versioning your plugin.
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "vpc_flow",
			Version: "0.1.0",
		}
	}

	// Probe allows the mapper to subscribe to logs with specific fields.
	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredEq(
						cm.Tuple[string, mapper.Scalar]{
							F0: "source.name",
							F1: log.ScalarStr("myservice"),
						},
					)}),
				None: cm.ToList([]mapper.Pred{}),
			},
		})
	}

	// ProcessLogs takes a batch of logs, transforms, and outputs bytes.
	mapper.Exports.ProcessLogs = func(input cm.List[log.Logview]) (res cm.Result[cm.List[uint8], cm.List[uint8], string]) {
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		// Copy out the slice so we own the backing array.
		// The cm.List view may be backed by a transient buffer that
		// can be reused or mutated after this call, so we take an owned copy.
		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			var out NetworkActivity

			lv := log.Logview(items[idx])

			// Required constants / defaults
			out.Metadata.Version = "1.5.0"
			out.Metadata.Product = Product{Name: "VPC Flow Logs", VendorName: "AWS"}
			out.CategoryUID = 4
			out.ClassUID = 4001
			out.SeverityID = 1
			out.ActivityID = 2
			out.TypeUID = 400102

			// Times
			if st := tangenthelpers.GetInt64(lv, "start_time"); st != nil {
				out.StartTime = *st
			}
			if et := tangenthelpers.GetInt64(lv, "end_time"); et != nil {
				out.EndTime = *et
			}
			if out.EndTime != 0 {
				out.Time = out.EndTime
			} else {
				out.Time = out.StartTime
			}

			// Endpoints
			if s := tangenthelpers.GetString(lv, "srcaddr"); s != nil {
				out.SrcEndpoint.IP = *s
			}
			if p := tangenthelpers.GetInt64(lv, "srcport"); p != nil {
				out.SrcEndpoint.Port = *p
			}
			if v := tangenthelpers.GetString(lv, "vpc_id"); v != nil {
				out.SrcEndpoint.VPCUID = *v
			}
			if s := tangenthelpers.GetString(lv, "dstaddr"); s != nil {
				out.DstEndpoint.IP = *s
			}
			if p := tangenthelpers.GetInt64(lv, "dstport"); p != nil {
				out.DstEndpoint.Port = *p
			}

			// Connection info
			out.ConnectionInfo.DirectionID = 0 // unknown by default
			if pn := tangenthelpers.GetString(lv, "protocol_name"); pn != nil {
				out.ConnectionInfo.ProtocolName = *pn
			} else if protoNum := tangenthelpers.GetInt64(lv, "protocol"); protoNum != nil {
				switch *protoNum {
				case 6:
					out.ConnectionInfo.ProtocolName = "tcp"
				case 17:
					out.ConnectionInfo.ProtocolName = "udp"
				default:
					out.ConnectionInfo.ProtocolName = ""
				}
			}

			// Traffic
			if b := tangenthelpers.GetInt64(lv, "bytes"); b != nil {
				out.Traffic.Bytes = *b
			}
			if pk := tangenthelpers.GetInt64(lv, "packets"); pk != nil {
				out.Traffic.Packets = *pk
			}

			// Serialize with Segment's encoding/json
			err := json.NewEncoder(buf).Encode(out)
			if err != nil {
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
