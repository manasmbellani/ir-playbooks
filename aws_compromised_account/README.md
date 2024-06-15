# AWS Compromised Account

## Analysis

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
