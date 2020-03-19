# GitHub Vul

[![Build Status](https://travis-ci.org/jwplayer/github-vul.svg?branch=master)](https://travis-ci.org/jwplayer/github-vul)

Enable GitHub vulnerability alerts for all repositories.

## Usage

```bash
# default usage: enable for all repositories with automated security fixes
github-vul -org=myorg -alerts=true -fixes=true

# enable for single respository
github-vul -org=myorg -alerts=true -fixes=true -repo=myrepo

# enable for all repositories but disable automated security fixes
github-vul -org=myorg -alerts=true -fixes=false

# enable for all repositories but do nothing with automated security fixes
github-vul -org=myorg -alerts=true


github-vul -help

  -alerts
      Boolean to enable/disable alerts (GITHUB_VUL_ALERTS)
  -dry
      Dry run (GITHUB_VUL_DRY)
  -fixes
      [Optional] Boolean to enable/disable automated (GITHUB_VUL_FIXES)
  -org string
      GitHub org (GITHUB_VUL_ORG)
  -repo string
      [Optional] Specify a repository
  -token string
      GitHub API token (GITHUB_VUL_TOKEN)
```

## Requirements

[Generate a personal access token](https://github.com/settings/tokens) with `repo` and `read:org` permissions.

## Installation

### Releases

Download the binary for your platform from the [releases](https://github.com/jwplayer/github-vul/releases) page.

### Docker

```sh
docker pull jwplayer/github-vul
docker run -it -e $GITHUB_VUL_TOKEN jwplayer/github-vul -alert=true -org=jwplayer -dry=true
```

### Go

```sh
go get -u github.com/jwplayer/github-vul
```

## License

GitHub Vul is provided under the [Apache License v2.0](./LICENSE).
