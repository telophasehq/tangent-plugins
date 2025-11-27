package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	tangent_sdk "github.com/telophasehq/tangent-sdk-go"
	"github.com/telophasehq/tangent-sdk-go/config"
	"github.com/telophasehq/tangent-sdk-go/http"
)

// easyjson:json
type Alert struct {
	Triggered bool `json:"triggered"`
}

// Tangent metadata
var Metadata = tangent_sdk.Metadata{
	Name:    "selfhosted-runner-outside-cidr",
	Version: "0.1.0",
}

// Limit to GitHub / Actions events
var selectors = []tangent_sdk.Selector{
	{
		Any: []tangent_sdk.Predicate{
			tangent_sdk.EqString("action", "org.register_self_hosted_runner"),
			tangent_sdk.EqString("action", "enterprise.register_self_hosted_runner"),
		},
	},
}

// Two modes:
// 1) Do not allow any self-hosted runners. Remove runners that are created.
// 2) Detect if a self-hosted runner is outside a CIDR. We can't kill it, so send slack alert.
func Detect(lvs []tangent_sdk.Log) ([]Alert, error) {
	var alerts []Alert
	allowedCIDR, ok := config.Get("allowed_cidr")
	if !ok {
		return nil, errors.New("allowed_cidr not configured")
	}
	slackChannel, ok := config.Get("slack_channel")
	if !ok {
		return nil, errors.New("slack_channel not configured")
	}
	for _, lv := range lvs {
		var alert Alert

		if allowedCIDR != "" {
			actorIP := lv.GetString("actor.ip_address")
			if !ipInAllowedCIDR(allowedCIDR, *actorIP) {
				alert.Triggered = true
				if slackChannel == "" {
					return nil, errors.New("no slack channel configured.")
				}
				postToSlack(slackChannel, lv.Log())
			}

			continue
		} else {
			alert.Triggered = true
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func init() {
	tangent_sdk.Wire[Alert](
		Metadata,
		selectors,
		nil,
		Detect,
	)
}

func ipInAllowedCIDR(allowedCIDR string, ipStr string) bool {
	_, network, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return network.Contains(ip)
}

func postToSlack(slackChannel, rawLog string) error {
	accessToken := os.Getenv("SLACK_ACCESS_TOKEN")
	if accessToken == "" {
		return fmt.Errorf("SLACK_ACCESS_TOKEN not set")
	}

	type slackPayload struct {
		Text    string `json:"text"`
		Channel string `json:"channel"`
	}
	body, err := json.Marshal(slackPayload{
		Text:    fmt.Sprintf("Alert: github self-hosted runner registered with IP not in CIDR: %s", rawLog),
		Channel: slackChannel,
	})
	if err != nil {
		return err
	}

	resp, err := http.Call(http.Request{
		ID:     "slack-alert",
		Method: http.MethodPost,
		URL:    "https://slack.com/api/chat.postMessage",
		Body:   body,
		Headers: []http.Header{
			{
				Name:  "Content-Type",
				Value: "application/json",
			},
			{
				Name:  "Authorization",
				Value: "Bearer " + accessToken,
			},
		},
	})

	if err != nil {
		return err
	}

	var result struct {
		OK      bool   `json:"ok"`
		TS      string `json:"ts"`
		Error   string `json:"error,omitempty"`
		Channel string `json:"channel"`
	}
	json.Unmarshal(resp.Body, &result)

	if !result.OK {
		return fmt.Errorf("failed to post to slack: %s", result.Error)
	}
	return nil
}

func main() {}
