package main

import (
	"bytes"
	"qradar_offense/internal/tangent/logs/log"
	"qradar_offense/internal/tangent/logs/mapper"
	"qradar_offense/tangenthelpers"
	"strconv"
	"sync"

	"github.com/segmentio/encoding/json"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
	"go.bytecodealliance.org/cm"
)

var (
	bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)

// legacy template removed; this mapper emits OCSF v1.5 SecurityFinding

func Wire() {
	// Metadata is for naming and versioning your plugin.
	mapper.Exports.Metadata = func() mapper.Meta {
		return mapper.Meta{
			Name:    "qradar_offense → ocsf.security_finding",
			Version: "0.2.0",
		}
	}

	// Probe allows the mapper to subscribe to logs with specific fields.
	mapper.Exports.Probe = func() cm.List[mapper.Selector] {
		return cm.ToList([]mapper.Selector{
			{
				Any: cm.ToList([]mapper.Pred{}),
				All: cm.ToList([]mapper.Pred{
					mapper.PredHas("id"),
					mapper.PredHas("description"),
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
		// The cm.List view may be backed by a transient buffer that
		// can be reused or mutated after this call, so we take an owned copy.
		var items []log.Logview
		items = append(items, input.Slice()...)
		for idx := range items {
			lv := log.Logview(items[idx])

			// Map times
			createdMs := getInt64(lv, "start_time")
			lastSeenMs := getInt64(lv, "last_updated_time")
			if lastSeenMs == 0 {
				lastSeenMs = createdMs
			}
			modifiedMs := lastSeenMs
			endMs := getInt64(lv, "last_persisted_time")

			// Title and description
			title := tangenthelpers.GetString(lv, "offense_source")
			if title == nil || *title == "" {
				title = tangenthelpers.GetString(lv, "description")
			}
			desc := tangenthelpers.GetString(lv, "description")

			// Finding info
			uid := ""
			if v := tangenthelpers.GetInt64(lv, "id"); v != nil {
				uid = itoa(*v)
			}

			var dataSources []string
			if n := tangenthelpers.Len(lv, "log_sources"); n != nil && *n > 0 {
				if name := tangenthelpers.GetString(lv, "log_sources[0].name"); name != nil {
					dataSources = append(dataSources, *name)
				}
			}

			// Severity from magnitude/credibility
			sevName, sevId := mapSeverity(lv)

			// Status from status field
			statusName := "open"
			statusId := int32(1)
			if s := tangenthelpers.GetString(lv, "status"); s != nil && (*s == "CLOSED" || *s == "CLOSE") {
				statusName = "closed"
				statusId = 4
			}

			// Activity based on status/time
			activityId := int32(1)
			activityName := "Create"
			typeUid := int64(2001)*100 + int64(activityId)
			typeName := "Security Finding: Create"
			if statusName == "closed" || endMs != 0 {
				activityId = 3
				activityName = "Close"
				typeUid = int64(2001)*100 + int64(activityId)
				typeName = "Security Finding: Close"
			}

			// Metadata
			prod := "QRadar SIEM"
			vendor := "IBM"
			md := ocsf.Metadata{Version: "1.5.0", Product: ocsf.Product{Name: &prod, VendorName: &vendor}, LogName: strPtr("Offense"), LogProvider: strPtr("IBM QRadar")}

			find := ocsf.Finding{
				Uid:           uid,
				Title:         strOr(title),
				Desc:          desc,
				CreatedTime:   createdMs,
				FirstSeenTime: createdMs,
				LastSeenTime:  lastSeenMs,
				ModifiedTime:  modifiedMs,
			}

			out := ocsf.SecurityFinding{
				ActivityId:   activityId,
				ActivityName: &activityName,
				CategoryUid:  2,
				CategoryName: strPtr("Findings"),
				ClassUid:     2001,
				ClassName:    strPtr("Security Finding"),
				Time:         chooseNonZero(endMs, lastSeenMs, createdMs),
				StartTime:    createdMs,
				EndTime:      endMs,
				Message:      desc,
				Metadata:     md,
				Severity:     &sevName,
				SeverityId:   int32(sevId),
				Status:       &statusName,
				StatusId:     &statusId,
				TypeUid:      typeUid,
				TypeName:     &typeName,
				Finding:      find,
				DataSources:  dataSources,
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

// helpers
func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func mapSeverity(lv log.Logview) (string, int) {
	// Map QRadar magnitude -> OCSF severity
	// magnitude: 0-3 low, 4-6 medium, 7-10 high
	if m := tangenthelpers.GetInt64(lv, "magnitude"); m != nil {
		v := *m
		switch {
		case v >= 7:
			return "high", 4
		case v >= 4:
			return "medium", 3
		case v > 0:
			return "low", 2
		}
	}
	return "unknown", 0
}

func strPtr(s string) *string { return &s }
func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func getInt64(lv log.Logview, path string) int64 {
	if v := tangenthelpers.GetInt64(lv, path); v != nil {
		return *v
	}
	return 0
}
func chooseNonZero(vals ...int64) int64 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
