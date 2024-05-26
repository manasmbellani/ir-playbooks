# Github - Compromised Account

## Containment

### Block github user's account

#### via curl / Github REST API

Generate the github personal access token as the user that is the owner for the organization

```
github_org=...
github_username=...
github_pat=...
username_to_block=...

auth_token=$(echo -n "$github_username:$github_pat" | base64)

# List blocked users
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/user/blocks

# Block user from an organization
curl -L \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/memberships/$username_to_block

# Block user from following in Github
curl -L \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/user/blocks/$username_to_block

# List any existing invitations for users for the organization and identify ones that may belong to he user
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/failed_invitations

# Cancel any invitations to the user by ID (get ID from output above e.g. '34397904')
github_invitation_id=...
curl -L \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Basic $auth_token" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/$github_org/invitations/$github_invitation_id
```
  
## Collection

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
