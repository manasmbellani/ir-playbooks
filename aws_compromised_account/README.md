# AWS Compromised Account

## Analysis

### Detect unusual EC2 instance start attempts

- Can be used to detect unusual activity e.g. for cryptomining
  
#### via AWS Cloudtrail Event Logs

```
# See `sourceIPAddress` and `userAgent` strings for detecting where unusual activity originated from
eventName: "RunInstances"
eventSource: "ec2.amazonaws.com"
```

### Detect EC2 Serial console Access Attempts

### via AWS CloudTrail Audit Logs

```
# userAgent, sourceIPAddress, userIdentity.userName, userIdentity.* are useful fields 
eventSource: "ec2-instance-connect.amazonaws.com"
eventName: SendSerialConsoleSSHPublicKey
```

Taken from [here](https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/)

### Detect creation of new users

Creation of new users could indicate persistence within the AWS environment.

#### via AWS CloudTrail Audit Logs

```
# userIdentity.arn is the user that created the user, AWS::IAM::User is the user that was created, requestParameters.userName is the user that was created
eventName: "CreateUser"
```

### Detect creation of access keys

Creation of access keys from unusual source can indicate persistence within the AWS environment.

#### via AWS CloudTrail Audit Logs

```
# requestParameters.userName contains the username for which access key was created
# responseElements.accessKey.accessKeyId is the ID of the key created
eventName: "CreateAccessKey"
```
