package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

// variables used to embed build information in the binary
var (
	BuildTime string
	BuildSHA  string
	Version   string
)

var crash = log.Fatalf

type owner struct {
	Login string `json:"login"`
}

type repository struct {
	Archived bool `json:"archived"`
	Name     string `json:"name"`
	Owner    owner  `json:"owner"`
}

// Executor provides runtime configuration and facilities
type Executor struct {
	client *http.Client
	token  string
	http   bool
	dry    bool
}

// NewExecutor returns a new executor of GitHub operations
func NewExecutor(token string, dry bool) *Executor {
	ex := Executor{
		client: &http.Client{},
		token:  token,
		dry:    dry,
	}

	return &ex
}

func (ex *Executor) makeRequest(method string, url string, acceptHeaders ...string) (res *http.Response, err error) {
	protocol := "https"
	if ex.http {
		protocol = "http"
	}

	req, err := http.NewRequest(method, protocol+"://api.github.com/"+url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "token "+ex.token)
	for _, header := range acceptHeaders {
		req.Header.Add("Accept", header)
	}
	res, _ = ex.client.Do(req)
	if res.StatusCode >= 400 {
		return res, errors.New(res.Status)
	}
	return res, nil
}

func (ex *Executor) listRepositories(org string) ([]repository, error) {
	repositories := make([]repository, 0, 1)

	for page, keepGoing := 1, true; keepGoing; page++ {
		res, err := ex.makeRequest("GET", "orgs/"+org+"/repos?type=all&sort=updated&direction=asc&per_page=100&page="+strconv.Itoa(page))

		if err != nil {
			return repositories, fmt.Errorf("failed to get repositories: %w\n", err)
		}

		d := json.NewDecoder(res.Body)
		var repos struct {
			Repositories []repository
		}
		err = d.Decode(&repos.Repositories)

		if err != nil {
			return repositories, fmt.Errorf("failed to parse repository: %w\n", err)
		}

		for _, repo := range repos.Repositories {
			repositories = append(repositories, repo)
		}

		if len(repos.Repositories) == 0 {
			break
		}
	}

	return repositories, nil
}

func (ex *Executor) checkEnabled(repo repository) (bool, error) {
	// https://developer.github.com/v3/repos/#enable-vulnerability-alerts
	res, err := ex.makeRequest("GET", "repos/"+repo.Owner.Login+"/"+repo.Name+"/vulnerability-alerts", "application/vnd.github.dorian-preview+json")

	switch res.StatusCode {
	case 404:
		return false, nil
	case 204:
		return true, nil
	default:
		return false, fmt.Errorf("failed to check vulnerability alerts config for repo %s: %w\n", repo.Name, err)
	}
}

func (ex *Executor) updateVulnerabilityAlerts(action string, repositories []repository) (int, error) {
	numUpdated := 0

	var method string

	switch action {
	case "enable":
		method = "PUT"
	case "disable":
		method = "DELETE"
	default:
		return 0, errors.New("action must be of value 'enable' or 'disable'")
	}

	for _, repo := range repositories {
		if repo.Archived {
			fmt.Printf("skipping archived repository %s\n", repo.Name)
			continue
		}

		isEnabled, err := ex.checkEnabled(repo)
		performAction := (!isEnabled && (action == "enable")) || (isEnabled && (action == "disable"))
		if !performAction {
			continue
		}

		if ex.dry {
			fmt.Printf("dry run: will update vulnerability alerts for repository %s\n", repo.Name)
			continue
		}

		// https://developer.github.com/v3/repos/#enable-vulnerability-alerts
		_, err = ex.makeRequest(method, "repos/"+repo.Owner.Login+"/"+repo.Name+"/vulnerability-alerts", "application/vnd.github.dorian-preview+json")
		if err != nil {
			return numUpdated, fmt.Errorf("failed to update vulnerability alerts for repo %s: %w\n", repo.Name, err)
		}

		fmt.Printf("updated vulnerability alerts for repository %s\n", repo.Name)

		numUpdated++
	}

	return numUpdated, nil
}

func (ex *Executor) updateSecurityFixes(fixes bool, repositories []repository) (int, error) {
	numUpdated := 0

	var method string

	if fixes {
		method = "PUT"
	} else {
		method = "DELETE"
	}

	for _, repo := range repositories {
		if ex.dry {
			fmt.Printf("dry run: will update automated security fixes for repository %s\n", repo.Name)
			continue
		}

		// https://developer.github.com/v3/repos/#enable-vulnerability-alerts
		_, err := ex.makeRequest(method, "repos/"+repo.Owner.Login+"/"+repo.Name+"/automated-security-fixes", "application/vnd.github.london-preview+json")
		if err != nil {
			return numUpdated, fmt.Errorf("failed to update automated security fixes alerts for repo %s: %w\n", repo.Name, err)
		}

		fmt.Printf("updated security fixes for repository %s\n", repo.Name)

		numUpdated++
	}

	return numUpdated, nil
}

func getConfig() struct {
	token, org, action string
	fixes, dry                bool
} {
	var config struct {
		token  string
		org    string
		action string
		fixes  bool
		dry    bool
	}

	for _, s := range []string{"GITHUB_VUL_TOKEN", "GITHUB_TOKEN"} {
		if os.Getenv(s) != "" {
			config.token = os.Getenv(s)
		}
	}

	if config.org == "" {
		config.org = os.Getenv("GITHUB_VUL_ORG")
	}

	if config.action == "" {
		config.action = os.Getenv("GITHUB_VUL_ACTION")
	}

	envDry := os.Getenv("GITHUB_VUL_DRY")

	if envDry != "" {
		r, err := strconv.ParseBool(envDry)
		if err == nil {
			config.dry = r
		}
	}

	envFixes := os.Getenv("GITHUB_VUL_FIXES")

	if envFixes != "" {
		r, err := strconv.ParseBool(envFixes)
		if err == nil {
			config.fixes = r
		}
	}

	return config
}

// Run finds all org repos and ensures vulnerability alerts are turned on
func Run(org string, action string, fixes bool, repo string, ex Executor) error {
	switch {
	case org == "":
		return errors.New("missing org")
	case action == "":
		return errors.New("missing action")
	}

	var err error
	var repositories []repository

	if repo == "" {
		// no repo is specified, just list all repositores in org
		repositories, err = ex.listRepositories(org)
		if err != nil {
			return err
		}
	} else {
		repositories = []repository{
			repository{
				Name: repo,
				Owner: owner{
					Login: org,
				},
			},
		}
	}

	numAlerts, err := ex.updateVulnerabilityAlerts(action, repositories)
	if err != nil {
		return err
	}

	fmt.Printf("updated alerts for %d repositories\n", numAlerts)

	numFixes, err := ex.updateSecurityFixes(fixes, repositories)
	if err != nil {
		return err
	}

	fmt.Printf("updated security fixes for %d repositories\n", numFixes)

	return nil
}

func setupUsage() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "github-vul v"+Version+" "+BuildTime+" "+BuildSHA+"\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	config := getConfig()
	var action = flag.String("action", config.action, "Action to perform [enable|disable] (GITHUB_VUL_ACTION)")
	var dry = flag.Bool("dry", config.dry, "Dry run (GITHUB_VUL_DRY)")
	var fixes = flag.Bool("fixes", config.fixes, "Enable automated security fixes (GITHUB_VUL_FIXES)")
	var org = flag.String("org", config.org, "GitHub org (GITHUB_VUL_ORG)")
	var repo = flag.String("repo", config.action, "Optional - Specify a repository")
	var token = flag.String("token", config.token, "GitHub API token (GITHUB_VUL_TOKEN)")
	setupUsage()
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(1)
	}
	ex := NewExecutor(*token, *dry)
	err := Run(*org, *action, *fixes, *repo, *ex)
	if err != nil {
		crash(err.Error())
	}
}
