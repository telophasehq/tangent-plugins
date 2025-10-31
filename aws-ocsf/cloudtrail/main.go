package main

import (
	"bytes"
	"cloudtrail/internal/tangent/logs/log"
	"cloudtrail/internal/tangent/logs/mapper"
	"cloudtrail/tangenthelpers"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

func Wire() {
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "aws-cloudtrail → ocsf.api_activity",
			Version: "0.1.0",
		}
	}

	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("eventName"),
					mapper.PredHas("eventSource"),
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

			// Core fields
			eventName := tangenthelpers.GetString(lv, "eventName")
			if eventName == nil || *eventName == "" {
				res.SetErr("missing eventName")
				return
			}
			eventSource := tangenthelpers.GetString(lv, "eventSource")
			errorCode := tangenthelpers.GetString(lv, "errorCode")
			userName := tangenthelpers.GetString(lv, "userIdentity.userName")
			acctID := tangenthelpers.GetString(lv, "userIdentity.accountId")
			sourceIP := tangenthelpers.GetString(lv, "sourceIPAddress")
			eventID := tangenthelpers.GetString(lv, "eventID")
			// Time
			var ts time.Time
			if p := tangenthelpers.GetString(lv, "eventTime"); p != nil {
				if t, err := time.Parse(time.RFC3339, *p); err == nil {
					ts = t
				}
			}
			if ts.IsZero() {
				ts = time.Now().UTC()
			}

			// Activity classification
			classUID := int32(6003)
			categoryUID := int32(6)
			className := "API Activity"
			categoryName := "Application Activity"
			activityID, activityName, typeUID, typeName := classifyAPIActivity(*eventName)

			status := "unknown"
			var statusID int32
			severity := "informational"
			var severityID int32 = 1
			if errorCode == nil || *errorCode == "" {
				status = "success"
				statusID = 1
			} else {
				status = "failure"
				statusID = 2
				severity = "medium"
				severityID = 3
			}

			// Actor
			var actor ocsf.Actor
			if userName != nil {
				actor = ocsf.Actor{
					AppName: eventSource,
					User:    &ocsf.User{Name: userName},
				}
				if acctID != nil {
					actor.User.Account = &ocsf.Account{
						TypeId: int32Ptr(10),
						Type:   stringPtr("AWS Account"),
						Uid:    acctID,
					}
				}
			} else {
				actor = ocsf.Actor{AppName: eventSource}
			}

			// API
			api := ocsf.API{
				Operation: *eventName,
				Service:   &ocsf.Service{Name: eventSource},
			}

			// Resources
			var resources []ocsf.ResourceDetails
			if n := tangenthelpers.Len(lv, "resources"); n != nil && *n > 0 {
				for i := 0; i < int(*n); i++ {
					arn := tangenthelpers.GetString(lv, fmt.Sprintf("resources[%d].ARN", i))
					typ := tangenthelpers.GetString(lv, fmt.Sprintf("resources[%d].type", i))
					if arn != nil && *arn != "" {
						resources = append(resources, ocsf.ResourceDetails{
							Name: arn,
							Type: typ,
							Uid:  arn,
						})
					}
				}
			}

			// Source endpoint
			srcEndpoint := ocsf.NetworkEndpoint{}
			if sourceIP != nil && *sourceIP != "" {
				srcEndpoint.Ip = sourceIP
			} else {
				srcEndpoint.SvcName = eventSource
			}

			metadata := ocsf.Metadata{
				Version:        "1.5.0",
				CorrelationUid: eventID,
			}

			out := ocsf.APIActivity{
				ActivityId:     activityID,
				ActivityName:   &activityName,
				Actor:          actor,
				Api:            api,
				CategoryName:   &categoryName,
				CategoryUid:    categoryUID,
				ClassName:      &className,
				ClassUid:       classUID,
				Status:         &status,
				StatusId:       &statusID,
				Resources:      resources,
				Severity:       &severity,
				SeverityId:     severityID,
				Metadata:       metadata,
				SrcEndpoint:    srcEndpoint,
				Time:           ts.UnixMilli(),
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

func classifyAPIActivity(eventName string) (int32, string, int, string) {
	classUID := 6003
	if hasAnyPrefix(eventName, "Create", "Add", "Put", "Insert") {
		return 1, "create", classUID*100 + 1, "API Activity: Create"
	}
	if hasAnyPrefix(eventName, "Get", "Describe", "List", "Search") {
		return 2, "read", classUID*100 + 2, "API Activity: Read"
	}
	if hasAnyPrefix(eventName, "Update", "Modify", "Set") {
		return 3, "update", classUID*100 + 3, "API Activity: Update"
	}
	if hasAnyPrefix(eventName, "Delete", "Remove") {
		return 4, "delete", classUID*100 + 4, "API Activity: Delete"
	}
	return 0, "unknown", classUID*100 + 0, "API Activity: Unknown"
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

func int32Ptr(i int32) *int32    { return &i }
func stringPtr(s string) *string { return &s }

func init() { Wire() }

func main() {}
