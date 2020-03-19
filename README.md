# GitHub Vul

Enable GitHub vulnerability alerts for all repositories.

## Usage

```bash
# default usage: enable for all repositores
github-vul -org=myorg -action=enable

# enable for single respostiory
github-vul -org=myorg -action=enable -repo=myrepo

github-vul -help

  -action string
      Action to perform [enable|disable] (GITHUB_VUL_ACTION)
  -dry
      Dry run (GITHUB_VUL_DRY)
  -fixes
      Enable automated security fixes (GITHUB_VUL_FIXES)
  -org string
      GitHub org (GITHUB_VUL_ORG)
  -repo string
      Optional - Specify a repository
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
docker run -it -e $GITHUB_VUL_TOKEN jwplayer/github-vul -action=enable -org=jwplayer -dry=true
```

### Go

```sh
go get -u github.com/jwplayer/github-vul
```

## License

GitHub Vul is provided under the [Apache License v2.0](./LICENSE).
