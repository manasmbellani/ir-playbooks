# Docker - compromised container

## Analysis

### Check capabilities of containers

#### via docker inspect

```
# See HostConfig.CapAdd
docker inspect $CONTAINER_ID 
```

#### via capsh

```
apt-get -y update && apt-get -y install libcap2-bin && capsh --print
```

https://stackoverflow.com/a/43622076

## TODO
- Analysis [Sysdig Steps](https://sysdig.com/blog/triaging-malicious-docker-container/)
