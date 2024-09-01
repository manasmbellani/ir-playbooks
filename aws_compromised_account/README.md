# AWS Compromised Account

## Collection

### Collect CloudTrail Events

Process and add new fields via timesketch_utils script [here](../gcp_compromised_pod/timesketch_utils)

#### via awscli / cloudtrail / lookup-events

```
START_TIME="2024-08-01T00:00:00Z"
END_TIME="2024-09-01T00:00:00Z"
AWS_PROFILE="default"
AWS_REGION="us-east-1"

aws cloudtrail lookup-events --start-time $START_TIME --end-time $END_TIME --profile $AWS_PROFILE --region $AWS_REGION > out-cloudtrail-events-$AWS_PROFILE-$AWS_REGION-$START_TIME-$END_TIME.json
```

#### via awscli / S3 

```
aws s3 cp s3://$BUCKET_NAME/ $LOCAL_DIR --recursive
```

## Analysis

### Detect unusual GuardDuty Events

#### via AWS Cloud Trail Event Logs / Guardduty

```
eventName: DeleteDetector
serviceName: guardduty.amazonaws.com
```

### Detect unusual EC2 connection attempt

- Anomalous activity could indicate access attempt which is not normal
  
#### via AWS Cloud Trail Event Logs / EC2 Instance Connect

```
# Typically created the first time when an EC2 is being accessed
eventName: SendSSHPublicKey
eventSource: ec2-instance-connect.amazonaws.com
```

### Detect unusual EC2 instance start / creation / run attempts

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

### Detect unusual commands being run

- Unusual usernames may indicate threat actors are executing commands
  
#### via AWS Cloudtrail Audit Logs / SSM

```
eventName: SendCommand
eventSource: ssm.amazonaws.com
```

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
