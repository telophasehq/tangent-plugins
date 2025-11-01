package main

import (
	"bytes"
	"sync"
	"time"

	"o365_exchange_messagetrace/internal/tangent/logs/log"
	"o365_exchange_messagetrace/internal/tangent/logs/mapper"
	"o365_exchange_messagetrace/tangenthelpers"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// MappingSpec:
// SenderAddress -> email.smtp_from; RecipientAddress -> email.smtp_to[0]; Subject -> email.subject; MessageId -> email.message_uid; Size -> email.size
// FromIP -> src_endpoint.ip; Received -> time (ms); metadata.original_time <- Received
// MessageTraceId -> message_trace_uid
// Fixed: activity Trace(4), category Network Activity(4), class Email Activity(4009), direction Unknown(0), severity Unknown(0), status Success(1), status_detail from Status
// metadata.product { name O365, vendor_name Microsoft }; metadata.version 1.4.0
// unmapped carries Index and Organization

// legacy structs removed; emit OCSF v1.5 EmailActivity

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "o365-exchange → ocsf.email_activity",
			Version: "0.2.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("MessageId"),
					mapper.PredHas("SenderAddress"),
					mapper.PredHas("RecipientAddress"),
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
			var timeMs int64
			var original string
			if v := tangenthelpers.GetString(lv, "Received"); v != nil {
				if t, err := time.Parse("2006-01-02T15:04:05.9999999", *v); err == nil {
					timeMs = t.UnixMilli()
					original = *v
				}
			}

			// Email
			email := ocsf.Email{}
			if v := tangenthelpers.GetString(lv, "MessageId"); v != nil {
				email.MessageUid = v
			}
			if v := tangenthelpers.GetInt64(lv, "Size"); v != nil {
				sz := *v
				email.Size = &sz
			}
			if v := tangenthelpers.GetString(lv, "SenderAddress"); v != nil {
				email.From = v
			}
			if v := tangenthelpers.GetString(lv, "RecipientAddress"); v != nil {
				email.To = []string{*v}
			}
			if v := tangenthelpers.GetString(lv, "Subject"); v != nil {
				email.Subject = v
			}

			// Source endpoint
			var src *ocsf.NetworkEndpoint
			if v := tangenthelpers.GetString(lv, "FromIP"); v != nil {
				src = &ocsf.NetworkEndpoint{Ip: v}
			}

			// Metadata
			prod := "O365"
			vendor := "Microsoft"
			uid := "7a56049d-9c79-46c4-a1ac-ce6dfe8f2005"
			md := ocsf.Metadata{Version: "1.5.0", Product: ocsf.Product{Name: &prod, VendorName: &vendor}, OriginalTime: &original, Uid: &uid}

			// Build EmailActivity
			dir := int32(0)
			st := int32(1)
			out := ocsf.EmailActivity{
				ActivityId:  4,
				CategoryUid: 4,
				ClassUid:    4009,
				DirectionId: dir,
				SeverityId:  int32(0),
				StatusId:    &st,
				Time:        timeMs,
				TypeUid:     400904,
				Email:       email,
				Metadata:    md,
				SrcEndpoint: src,
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
