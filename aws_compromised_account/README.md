# AWS Compromised Account

## Analysis

### Detect creation of new users

Creation of new users could indicate persistence within the environment

#### via AWS CloudTrail Audit Logs

```
# userIdentity.arn is the user that created the user, AWS::IAM::User is the user that was created, requestParameters.userName is the user that was created
eventName: "CreateUser"
```
