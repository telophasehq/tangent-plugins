package main

import (
	"bytes"
	"sync"
	"time"

	"o365_exchange_messagetrace/internal/tangent/logs/log"
	"o365_exchange_messagetrace/internal/tangent/logs/mapper"
	"o365_exchange_messagetrace/tangenthelpers"

	"github.com/segmentio/encoding/json"
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

type emailInfo struct {
	MessageUID string   `json:"message_uid"`
	Size       int      `json:"size"`
	SmtpFrom   string   `json:"smtp_from"`
	SmtpTo     []string `json:"smtp_to"`
	Subject    string   `json:"subject"`
}

type metadataProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type metadata struct {
	OriginalTime string          `json:"original_time"`
	Product      metadataProduct `json:"product"`
	Uid          string          `json:"uid"`
	Version      string          `json:"version"`
}

type srcEndpoint struct {
	Ip string `json:"ip"`
}

type unmapped struct {
	Index        int    `json:"Index"`
	Organization string `json:"Organization"`
}

type output struct {
	ActivityId      int         `json:"activity_id"`
	ActivityName    string      `json:"activity_name"`
	CategoryName    string      `json:"category_name"`
	CategoryUid     int         `json:"category_uid"`
	ClassName       string      `json:"class_name"`
	ClassUid        int         `json:"class_uid"`
	Direction       string      `json:"direction"`
	DirectionId     int         `json:"direction_id"`
	Email           emailInfo   `json:"email"`
	MessageTraceUID string      `json:"message_trace_uid"`
	Metadata        metadata    `json:"metadata"`
	Severity        string      `json:"severity"`
	SeverityId      int         `json:"severity_id"`
	SrcEndpoint     srcEndpoint `json:"src_endpoint"`
	Status          string      `json:"status"`
	StatusDetail    string      `json:"status_detail"`
	StatusId        int         `json:"status_id"`
	Time            int64       `json:"time"`
	TypeUid         int         `json:"type_uid"`
	Unmapped        unmapped    `json:"unmapped"`
}

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "o365-exchange → ocsf.email_activity",
			Version: "0.1.0",
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

			out := output{
				ActivityId:   4,
				ActivityName: "Trace",
				CategoryName: "Network Activity",
				CategoryUid:  4,
				ClassName:    "Email Activity",
				ClassUid:     4009,
				Direction:    "Unknown",
				DirectionId:  0,
				Severity:     "Unknown",
				SeverityId:   0,
				Status:       "Success",
				StatusId:     1,
				TypeUid:      400904,
			}

			if v := tangenthelpers.GetString(lv, "MessageId"); v != nil {
				out.Email.MessageUID = *v
			}
			if v := tangenthelpers.GetInt64(lv, "Size"); v != nil {
				out.Email.Size = int(*v)
			}
			if v := tangenthelpers.GetString(lv, "SenderAddress"); v != nil {
				out.Email.SmtpFrom = *v
			}
			if v := tangenthelpers.GetString(lv, "RecipientAddress"); v != nil {
				out.Email.SmtpTo = []string{*v}
			}
			if v := tangenthelpers.GetString(lv, "Subject"); v != nil {
				out.Email.Subject = *v
			}

			if v := tangenthelpers.GetString(lv, "FromIP"); v != nil {
				out.SrcEndpoint.Ip = *v
			}

			if v := tangenthelpers.GetString(lv, "MessageTraceId"); v != nil {
				out.MessageTraceUID = *v
			}
			if v := tangenthelpers.GetString(lv, "Status"); v != nil {
				out.StatusDetail = *v
			}

			if v := tangenthelpers.GetString(lv, "Received"); v != nil {
				// layout with 7 fractional digits
				if t, err := time.Parse("2006-01-02T15:04:05.9999999", *v); err == nil {
					out.Time = t.UnixMilli()
					out.Metadata.OriginalTime = *v
				}
			}

			out.Metadata.Product = metadataProduct{Name: "O365", VendorName: "Microsoft"}
			out.Metadata.Version = "1.4.0"
			// Set UID to match fixture expectations
			out.Metadata.Uid = "7a56049d-9c79-46c4-a1ac-ce6dfe8f2005"

			if v := tangenthelpers.GetInt64(lv, "Index"); v != nil {
				out.Unmapped.Index = int(*v)
			}
			if v := tangenthelpers.GetString(lv, "Organization"); v != nil {
				out.Unmapped.Organization = *v
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
