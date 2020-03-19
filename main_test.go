package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func testClient(handler http.Handler) (*http.Client, func()) {
	server := httptest.NewServer(handler)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
		},
	}
	return client, server.Close
}

type mockHTTPResponse struct {
	method     string
	URL        string
	body       string
	StatusCode int
}

func (r mockHTTPResponse) String() string {
	return r.method + " " + r.URL
}

func getResponse(responses []mockHTTPResponse, method string, url string) mockHTTPResponse {
	for _, res := range responses {
		if res.method == method && res.URL == url {
			return res
		}
	}

	return mockHTTPResponse{}
}

func TestConfig(t *testing.T) {
	os.Setenv("GITHUB_TOKEN", "xyzzy")
	os.Setenv("GITHUB_VUL_ORG", "foo")
	os.Setenv("GITHUB_VUL_ALERTS", "true")
	os.Setenv("GITHUB_VUL_DRY", "true")

	config := getConfig()

	if config.org != "foo" {
		t.Errorf("Expected getConfig() to set org to foo")
	}

	if !config.alerts {
		t.Errorf("Expected getConfig() to set alerts to true")
	}

	if config.token != "xyzzy" {
		t.Errorf("Expected getConfig() to set token to xyzzy")
	}

	if !config.dry {
		t.Errorf("Expected getConfig() to set dry to true")
	}

	os.Unsetenv("GITHUB_TOKEN")
	os.Unsetenv("GITHUB_VUL_ALERTS")
	os.Unsetenv("GITHUB_VUL_DRY")

	os.Setenv("GITHUB_VUL_ORG", "abc")
	os.Setenv("GITHUB_VUL_ALERTS", "true")
	os.Setenv("GITHUB_VUL_TOKEN", "token")
	defer os.Unsetenv("GITHUB_VUL_ORG")
	defer os.Unsetenv("GITHUB_VUL_ALERTS")
	defer os.Unsetenv("GITHUB_VUL_TOKEN")

	config = getConfig()

	if config.org != "abc" {
		t.Errorf("Expected getConfig() to set org to abc")
	}

	if config.token != "token" {
		t.Errorf("Expected getConfig() to set token to token")
	}

	if config.alerts != true {
		t.Errorf("Expected getConfig() to set alerts to true")
	}

	if config.dry != false {
		t.Errorf("Expected getConfig() to set dry to false")
	}
}

func TestUpdateVulnerabilityAlerts(t *testing.T) {
	ex := NewExecutor("token", false)
	n, err := ex.updateVulnerabilityAlerts(true, []repository{
		repository{
			Name: "repo",
			Owner: owner{
				Login: "org",
			},
		},
	})

	if n != 0 {
		t.Errorf("Expected enabled repositories to equal 0 due to error")
	}

	if err == nil {
		t.Errorf("Expected error due to misconfigured executor")
	}
}

func TestUpdateSecurityFixes(t *testing.T) {
	ex := NewExecutor("token", false)
	n, err := ex.updateSecurityFixes(true, []repository{
		repository{
			Name: "repo",
			Owner: owner{
				Login: "org",
			},
		},
	})

	if n != 0 {
		t.Errorf("Expected enabled repositories to equal 0 due to error")
	}

	if err == nil {
		t.Errorf("Expected error due to misconfigured executor")
	}
}

func TestDryRun(t *testing.T) {
	ex := NewExecutor("token", true)
	n, _ := ex.updateVulnerabilityAlerts(true, []repository{
		repository{
			Name: "repo",
		},
	})
	if n != 0 {
		t.Errorf("Expected no action")
	}
}

func TestListRepositories(t *testing.T) {
	repos := make([]repository, 100)

	for i := range repos {
		repos[i].Name = "Repo " + strconv.Itoa(i+1)
	}

	firstPageJSON, _ := json.Marshal(repos)
	firstPageResponse := mockHTTPResponse{
		method: "GET",
		URL:    "/orgs/org/repos?type=all&sort=updated&direction=asc&per_page=100&page=1",
		body:   string(firstPageJSON),
	}

	var k int
	for i := range repos {
		k = i + 100
		repos[i].Name = "Repo " + strconv.Itoa(k+1)
	}

	secondPageJSON, _ := json.Marshal(repos)
	secondPageResponse := mockHTTPResponse{
		method: "GET",
		URL:    "/orgs/org/repos?type=all&sort=updated&direction=asc&per_page=100&page=2",
		body:   string(secondPageJSON),
	}

	thirdPageResponse := mockHTTPResponse{
		method: "GET",
		URL:    "/orgs/org/repos?type=all&sort=updated&direction=asc&per_page=100&page=3",
		body:   `[]`,
	}

	responses := []mockHTTPResponse{firstPageResponse, secondPageResponse, thirdPageResponse}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := getResponse(responses, r.Method, r.URL.String())

		if res.method == "" {
			t.Fatalf(r.URL.String())
		}

		_, err := w.Write([]byte(res.body))

		if err != nil {
			t.Errorf(err.Error())
		}
	})
	client, teardown := testClient(handler)
	defer teardown()

	ex := NewExecutor("token", false)
	ex.client = client
	ex.http = true

	repositories, _ := ex.listRepositories("org")

	if len(repositories) != 200 {
		t.Errorf("Expected only 200 repositories, got %d", len(repositories))
	}
}

func TestRun(t *testing.T) {
	expectedRequests := make([]string, 0, 1)

	responses := []mockHTTPResponse{
		mockHTTPResponse{
			method: "GET",
			URL:    "/orgs/org/repos?type=all&sort=updated&direction=asc&per_page=100&page=1",
			body: `[
				{
					"name": "repo1",
					"owner": {
						"login": "org"
					}
				},
				{
					"name": "repo2",
					"owner": {
						"login": "org"
					}
				}
			]`,
			StatusCode: 200,
		},
		mockHTTPResponse{
			method:     "GET",
			URL:        "/orgs/org/repos?type=all&sort=updated&direction=asc&per_page=100&page=2",
			body:       `[]`,
			StatusCode: 200,
		},
		mockHTTPResponse{
			method:     "PUT",
			URL:        "/repos/org/repo1/vulnerability-alerts",
			body:       "",
			StatusCode: 204,
		},
		mockHTTPResponse{
			method:     "PUT",
			URL:        "/repos/org/repo2/vulnerability-alerts",
			body:       "",
			StatusCode: 204,
		},
		mockHTTPResponse{
			method:     "PUT",
			URL:        "/repos/org/repo1/automated-security-fixes",
			body:       "",
			StatusCode: 204,
		},
		mockHTTPResponse{
			method:     "PUT",
			URL:        "/repos/org/repo2/automated-security-fixes",
			body:       "",
			StatusCode: 204,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := getResponse(responses, r.Method, r.URL.String())

		if res.method == "" {
			t.Fatalf(r.URL.String())
		}

		expectedRequests = append(expectedRequests, res.String())

		w.WriteHeader(res.StatusCode)
		_, err := w.Write([]byte(res.body))

		if err != nil {
			t.Errorf(err.Error())
		}
	})
	client, teardown := testClient(handler)
	defer teardown()

	ex := NewExecutor("token", false)
	ex.client = client
	ex.http = true

	err := Run("org", true, true, "", *ex)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = Run("org", true, true, "repo1", *ex)
	if err != nil {
		t.Errorf(err.Error())
	}

	for _, r := range responses {
		found := false
		for _, er := range expectedRequests {
			if r.String() == er {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected request: " + r.String())
		}
	}

	err = Run("", true, true, "", *ex)

	if err == nil {
		t.Errorf("Expected error on missing org")
	}
}

func TestUsage(t *testing.T) {
	setupUsage()
}

func TestMainFn(t *testing.T) {
	_crash := crash

	defer func() { crash = _crash }()

	crash = func(msg string, v ...interface{}) {
		if msg == "" {
			t.Errorf("Expected error")
		}
	}

	main()
}
