package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	tangent_sdk "github.com/telophasehq/tangent-sdk-go"
	"github.com/telophasehq/tangent-sdk-go/config"
	"github.com/telophasehq/tangent-sdk-go/http"
	"github.com/telophasehq/tangent-sdk-go/lock"
)

type NPMWorkflowConfig struct {
	Repo     string `json:"repo"`
	Workflow string `json:"workflow"`
}

// easyjson:json
type Alert struct {
	// High-level verdict
	Triggered bool `json:"triggered"`

	// NPM publish info
	Package     *string `json:"package,omitempty"`
	Version     *string `json:"version,omitempty"`
	PublishedAt *string `json:"published_at,omitempty"`

	// Mitigation status fields added
	UnpublishSuccess bool   `json:"unpublish_success"`
	KeyDeleteSuccess bool   `json:"key_delete_success"`
	MitigationLog    string `json:"mitigation_log,omitempty"`
}

// Tangent metadata
var Metadata = tangent_sdk.Metadata{
	Name:    "npm-ci-correlation-detector",
	Version: "0.1.0",
}

// We only care about structured logs that represent an npm publish event.
var selectors = []tangent_sdk.Selector{
	{
		All: []tangent_sdk.Predicate{
			tangent_sdk.EqString("kind", "npm_package_version"),
		},
	},
}

// Detect correlates npm publish logs with GitHub Actions workflow runs
func Detect(lv tangent_sdk.Log) (Alert, error) {
	var alert Alert

	slackChannel, ok := config.Get("slack_channel")
	if !ok {
		return Alert{}, errors.New("slack_channel not configured")
	}

	shouldUnpublish, _ := config.Get("unpublish")

	pkg := lv.GetString("npm.name")
	if pkg == nil {
		err := postToSlack(slackChannel, fmt.Sprintf("Alert: package name missing from npm logs %s", lv.Log()))
		if err != nil {
			return alert, err
		}
		return alert, err
	}

	ver := lv.GetString("npm.version")
	if ver == nil {
		err := postToSlack(slackChannel, fmt.Sprintf("Alert: version missing from npm logs %s", lv.Log()))
		if err != nil {
			return alert, err
		}
		return alert, err
	}

	publishedAtStr := lv.GetString("npm.time")

	alert.Package = pkg
	alert.Version = ver
	alert.PublishedAt = publishedAtStr

	// Case: package was published outside a git repo.
	gitSha := lv.GetString("npm.gitHead")
	if gitSha == nil {
		err := alertWorkflow(*pkg, *ver, shouldUnpublish, slackChannel, lv.Log())
		if err != nil {
			fmt.Printf("Error on alert: %v\n", err)
		}

		alert.Triggered = true
		return alert, nil
	}

	githubConfigStr, ok := config.Get(*pkg)
	var githubConfig NPMWorkflowConfig
	err := json.Unmarshal([]byte(githubConfigStr), &githubConfig)
	if err != nil {
		return alert, err
	}

	// Case: package was published outside of expected workflow.
	if githubConfig.Repo != "" && githubConfig.Workflow != "" {
		ok, err := fetchRun(githubConfig.Repo, githubConfig.Workflow, *gitSha)
		if err != nil {

			fmt.Printf("Error fetching github runs: %v\n", err)
			fmt.Println(lv.Log())
			return alert, err
		}

		if !ok {
			err := alertWorkflow(*pkg, *ver, shouldUnpublish, slackChannel, lv.Log())
			if err != nil {
				fmt.Printf("Error on alert: %v\n", err)
			}
		}
	}

	if !ok {
		alert.Triggered = true

		err := alertWorkflow(*pkg, *ver, shouldUnpublish, slackChannel, lv.Log())
		if err != nil {
			fmt.Printf("Error on alert: %v\n", err)
		}
	}

	return alert, nil
}

func init() {
	tangent_sdk.Wire[Alert](
		Metadata,
		selectors,
		Detect,
		nil,
	)
}

func main() {}

func alertWorkflow(pkg, ver, shouldUnpublish, slackChannel, log string) error {
	ok := lock.Acquire(pkg)
	for !ok {
		time.Sleep(100 * time.Millisecond)
		ok = lock.Acquire(pkg)
	}

	defer func() {
		lock.Release(pkg)
	}()

	fmt.Println("package published outside git workflow", pkg, ver)
	if shouldUnpublish == "true" {
		err := unpublish(pkg, ver)
		if err != nil {
			fmt.Printf("npm unpublish error: %v\n", err)
			err := postToSlack(slackChannel, fmt.Sprintf("Alert: Failed to unpublish package: %v", err))
			if err != nil {
				return err
			}
		}

		fmt.Println("package unpublished", pkg, ver)
	}
	err := postToSlack(slackChannel, fmt.Sprintf("Alert: NPM package published outside CI: ```%s```", log))
	if err != nil {
		return err
	}

	return nil
}

func postToSlack(slackChannel, msg string) error {
	accessToken := os.Getenv("SLACK_ACCESS_TOKEN")
	if accessToken == "" {
		return fmt.Errorf("SLACK_ACCESS_TOKEN not set")
	}

	type slackPayload struct {
		Text    string `json:"text"`
		Channel string `json:"channel"`
	}
	body, err := json.Marshal(slackPayload{
		Text:    msg,
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

func getNPMPackage(pkg, accessToken string) (map[string]interface{}, error) {
	pkg = url.PathEscape(pkg)
	packageUrl := fmt.Sprintf("https://registry.npmjs.org/%s?write=true", pkg)

	resp, err := http.Call(http.Request{
		Method: http.MethodGet,
		URL:    packageUrl,
		Headers: []http.Header{
			{
				Name:  "Authorization",
				Value: "Bearer " + accessToken,
			},
			{Name: "npm-command", Value: "unpublish"},
			{Name: "npm-auth-type", Value: "web"},
			{Name: "Accept", Value: "*/*"},
		},
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("npm get revision failed: %s %s", pkg, string(resp.Body))
	}

	var packageDoc map[string]interface{}
	err = json.Unmarshal(resp.Body, &packageDoc)
	if err != nil {
		return nil, err
	}

	return packageDoc, nil
}

func unpublish(pkg, ver string) error {
	accessToken := os.Getenv("NPM_TOKEN")
	if accessToken == "" {
		return fmt.Errorf("NPM_TOKEN not set")
	}

	packageDoc, err := getNPMPackage(pkg, accessToken)
	if err != nil {
		return err
	}

	// Sometimes two packages will be unpublished at once.
	if vs, ok := packageDoc["versions"].(map[string]interface{}); ok {
		if _, exists := vs[ver]; !exists {
			return nil
		}
	}
	rev := packageDoc["_rev"].(string)
	delete(packageDoc["versions"].(map[string]interface{}), ver)

	if dt, ok := packageDoc["dist-tags"].(map[string]interface{}); ok {
		if latest, ok2 := dt["latest"].(string); ok2 && latest == ver {
			if vs, ok3 := packageDoc["versions"].(map[string]interface{}); ok3 && len(vs) > 0 {
				keys := make([]string, 0, len(vs))
				for k := range vs {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				dt["latest"] = keys[len(keys)-1]
			} else {
				delete(dt, "latest")
			}
		}
	}

	newPackageDoc, err := json.Marshal(packageDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal new json doc: %v", packageDoc)
	}

	encodedPkg := url.PathEscape(pkg)
	putURL := fmt.Sprintf(
		"https://registry.npmjs.org/%s/-rev/%s",
		encodedPkg,
		rev,
	)
	resp, err := http.Call(http.Request{
		Method: http.MethodPut,
		URL:    putURL,
		Body:   newPackageDoc,
		Headers: []http.Header{
			{
				Name:  "authorization",
				Value: "Bearer " + accessToken,
			},
			{Name: "user-agent", Value: "npm/11.4.2 node/v24.3.0 darwin arm64 workspaces/false"},
			{Name: "npm-command", Value: "unpublish"},
			{Name: "npm-auth-type", Value: "web"},
			{Name: "content-type", Value: "application/json"},
			{Name: "Accept", Value: "*/*"},
		},
	})
	if resp.Status != 200 {
		return fmt.Errorf("unpublish put revision failed: %s, %s: %s", pkg, ver, string(resp.Body))
	}

	updatedPackageDoc, err := getNPMPackage(pkg, accessToken)
	if err != nil {
		return err
	}
	updatedRev := updatedPackageDoc["_rev"].(string)

	baseName := pkg[strings.LastIndex(pkg, "/")+1:]
	tarball := fmt.Sprintf("%s-%s.tgz", baseName, ver)

	deleteURL := fmt.Sprintf(
		"https://registry.npmjs.org/%s/-/%s/-rev/%s",
		pkg,
		tarball,
		updatedRev,
	)

	resp, err = http.Call(http.Request{
		Method: http.MethodDelete,
		URL:    deleteURL,
		Headers: []http.Header{
			{
				Name:  "authorization",
				Value: "Bearer " + accessToken,
			},
			{Name: "user-agent", Value: "npm/11.4.2 node/v24.3.0 darwin arm64 workspaces/false"},
			{Name: "npm-command", Value: "unpublish"},
			{Name: "npm-auth-type", Value: "web"},
			{Name: "Accept", Value: "*/*"},
		},
	})

	if err != nil {
		return err
	}
	if resp.Status != 200 {
		return fmt.Errorf("unpublish npm package failed: %s, %s: %s", pkg, ver, string(resp.Body))
	}

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	json.Unmarshal(resp.Body, &result)

	if !result.Success {
		return fmt.Errorf("unpublish npm package failed: %s, %s: %s", pkg, ver, string(resp.Body))
	}
	return nil
}

func fetchRun(repo, workflow, sha string) (bool, error) {
	if repo == "" || sha == "" {
		return false, errors.New("github repo, and sha are required")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return false, fmt.Errorf("GITHUB_TOKEN not set in environment")
	}

	req := http.Request{
		ID:     "fetch-workflow",
		Method: http.MethodGet,
		URL:    fmt.Sprintf("https://api.github.com/repos/%s/actions/workflows/%s/runs?head_sha=%s", repo, workflow, sha),
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
		return false, err
	}
	if resp.Error != nil {
		return false, errors.New(*resp.Error)
	}

	var runsResp struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal(resp.Body, &runsResp); err != nil {
		return false, err
	}

	if runsResp.TotalCount == 0 {
		return false, nil
	}

	return true, nil
}
