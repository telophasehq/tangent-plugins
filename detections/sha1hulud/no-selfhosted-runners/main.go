package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Name:    "kill-selfhosted-runners",
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

// Detects self-hosted runner creation in Github.
// Can alert or directly remove the runners.
func Detect(lvs []tangent_sdk.Log) ([]Alert, error) {
	var alerts []Alert

	orgID, ok := config.Get("github_org_id")
	if !ok {
		return nil, errors.New("github_org_id not configured")
	}
	slackChannel, ok := config.Get("slack_channel")
	if !ok {
		return nil, errors.New("slack_channel not configured")
	}
	for _, lv := range lvs {
		alerts = append(alerts, Alert{Triggered: true})

		postToSlack(slackChannel, lv.Log())
	}

	if killRunners, ok := config.Get("kill_runners"); ok && killRunners == "true" {
		if orgID == "" {
			return nil, errors.New("github_org_id is not set in plugin config.")
		}
		if err := killAllRunners(orgID); err != nil {
			return nil, err
		}
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

type githubRunnerLabel struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type githubRunner struct {
	ID        int                 `json:"id"`
	Name      string              `json:"name"`
	OS        string              `json:"os"`
	Status    string              `json:"status"`
	Busy      bool                `json:"busy"`
	Ephemeral bool                `json:"ephemeral"`
	Labels    []githubRunnerLabel `json:"labels"`
}

type githubListRunnersResponse struct {
	TotalCount int            `json:"total_count"`
	Runners    []githubRunner `json:"runners"`
}

func fetchRunners(org string) ([]int, error) {
	if org == "" {
		return nil, fmt.Errorf("missing org (%q)", org)
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN not set in environment")
	}

	req := http.Request{
		ID:     "fetch-runner",
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://api.github.com/orgs/%s/actions/runners", org),
		Headers: []http.Header{
			{
				Name:  "Authorization",
				Value: "Bearer " + token,
			},
			{
				Name:  "Accept",
				Value: "application/vnd.github+json",
			},
			{
				Name:  "User-Agent",
				Value: "Tangent",
			},
		},
	}

	resp, err := http.Call(req)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, errors.New(*resp.Error)
	}

	var runnerResp githubListRunnersResponse
	if err := json.Unmarshal(resp.Body, &runnerResp); err != nil {
		return nil, err
	}

	var runnerIDS []int
	for _, runner := range runnerResp.Runners {
		runnerIDS = append(runnerIDS, runner.ID)
	}

	return runnerIDS, nil
}

func killAllRunners(orgID string) error {
	runnerIDs, err := fetchRunners(orgID)
	if err != nil {
		return err
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN not set in environment")
	}

	var reqs []http.Request
	for _, runnerID := range runnerIDs {
		reqs = append(reqs, http.Request{
			ID:     fmt.Sprintf("kill-%d", runnerID),
			Method: http.MethodDelete,
			URL:    fmt.Sprintf("https://api.github.com/orgs/%s/actions/runners/%d", orgID, runnerID),
			Headers: []http.Header{
				{
					Name:  "Authorization",
					Value: "Bearer " + token,
				},
				{
					Name:  "Accept",
					Value: "application/vnd.github+json",
				},
				{
					Name:  "User-Agent",
					Value: "Tangent",
				},
			},
		})
	}

	resps, err := http.CallBatch(reqs)
	if err != nil {
		return err
	}
	for _, resp := range resps {
		if resp.Error != nil {
			return errors.New(*resp.Error)
		}
	}

	return nil
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
