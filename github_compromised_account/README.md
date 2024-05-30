# Github - Compromised Account

## Containment

### Block github user's account

#### via curl / Github REST API

Generate the github personal access token as the user that is the owner for the organization.

```
github_org=...
github_username=...
github_token=...
username_to_block=...

# List blocked users
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $github_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/user/blocks

# Block user from an organization
curl -L \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $github_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/memberships/$username_to_block

# Block user from following in Github
curl -L \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $github_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/user/blocks/$username_to_block
```

#### via UI

`Profile Photo > Settings > Access > Moderation > Blocked Users`

### Cancel failed organization invitations

#### via curl / Github REST API

```
# List any existing invitations for users for the organization and identify ones that may belong to he user
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/failed_invitations
```

```
# Cancel any invitations to the user by ID (get ID from output above e.g. '34397904')
github_invitation_id=...
curl -L \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/invitations/$github_invitation_id
```

### via UI

Profile > Your Organizations > Select Organization > People > Invitations

## Collection

### Collect Logs

#### via Github API Logs

Replace `$organization` with Github token - this will provide 100 pages and 
```
# Call this again with the specified cursor returned in response
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $github_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/orgs/$organization/audit-log?per_page=100&include=all" | tee /tmp/out.json
```

Taken from [here](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs?apiVersion=2022-11-28#get-the-audit-log-for-an-organization)

## Analysis

### List SSH Signing Keys for user

#### via curl

```
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/users/$github_username/ssh_signing_keys
```

### List SSH Keys for the user

User can leverage these keys to clone repositories. These cannot be removed by the owner, so one may have to ensure that access is not available for the account.

#### via curl

```
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/users/$github_username/keys
```

## Eradication

## Recovery
