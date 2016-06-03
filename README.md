# Configuring CloudInsight AWS CloudTrail Monitoring
## Setup
### Mac OS X Installation Requirements
```ci_setup_cloudtrail``` requires Python 2.7 or higher.

#### Install Python

```$ brew install python```

**Note:** The latest version of Mac OS X, El Capitan, comes with Python 2.7 out of the box. 

#### Install the latest version of boto3
```$ pip install boto3```

If you already have ```boto3``` installed, make sure to upgrade it to the latest version. This utility has been tested with boto3 version 1.3.1

```$ pip install --upgrade boto3```

**Note:** Homebrew installs ```pip``` for you.


### Linux Installation Requirements	

#### Install Python
Install python package using your OS package installation system (dpkg or rpm). Make sure the version of python is 2.7 or higher.

**Note:** The latest versions of CentOS, Fedora, Redhat Enterprise (RHEL) and Ubuntu come with Python 2.7 out of the box.

#### Install the latest version of boto3
```$ pip install boto3```

If you already have ```boto3``` installed, make sure to upgrade it to the latest version. This utility has been tested with boto3 version 1.3.1

```$ pip install --upgrade boto3```

**Note:** ```pip``` comes preinstalled with python v 2.7 or higher

### Install CloudInsight AWS CloudTrail Monitoring Utility
Download ```ci_setup_cloudtrail``` utility:

```git clone git@github.com:alertlogic/ci_setup_cloudtrail.git ci_setup_cloudtrail```

Give yourself permission to exectute ```ci_setup_cloudtrail.py```

```
$ cd ci_setup_cloudtrail 
$ chmod 755 ci_setup_cloudtrail.py
```

### Run CloudInsight AWS CloudTrail Monitoring Utility
#### Prerequisites
1. Ensure correct AWS CloudTrail setup in the account you want CloudInsight to monitor.  
1.1. Make sure AWS CloudTrail is setup to send notifications to AWS SNS. Preferably SNS Topic should exists in the same account as the S3 bucket where AWS CloudTrail is storing logs.  
For detailed instructions see: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-cloudtrail-to-send-notifications.html  
1.2. Ensure that AWS CloudTrail has permissions to send notifications to SNS Topic. For detailed instructions see: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-permissions-for-sns-notifications.html  
2. **Switch to an account that owns S3 bucket where AWS CloudTrail logs are stored.**  
3. Create SQS Queues for each region you want CloudInsight to monitor and subscribe to the SNS Topic used to receive AWS CloudTrail notifications. Follow detailed instructions see: http://docs.aws.amazon.com/sns/latest/dg/SendMessageToSQS.html   
4. Create a cross-account role to give CloudInsight permission to access AWS CloudTrail logs.    
4.1. Create IAM Policy to be used by cross-account role. Use the policy document below and make sure to substitute strings in ```<>``` with your account's values.  
```  
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReceiveSQSNotifications",
            "Effect": "Allow",
            "Action": [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage"
            ],
            "Resource": "arn:aws:sqs:*:<YOUR ACCOUNT ID>:<SQS QUEUE NAME>*"
        }
    ]
}
```  
4.2. Create a cross-account role  
4.2.1. CloudInsight AWS Account ID: 733251395267  
4.2.2. Pick Extrenal ID  
4.2.3. Choose policy created in step 1.1 and create IAM Role.
4.3. Update S3 bucket where CloudTrail logs are stored to include the following statements
```
{
	"Sid": "GetCloudTrailObjects",
	"Effect": "Allow",
	"Principal": {
		"AWS": "<CROSS-ACCOUNT ROLE ARN>"
	},
	"Action": [
		"s3:GetObjectVersionAcl",
		"s3:GetObject",
		"s3:GetObjectAcl"
	],
	"Resource": "arn:aws:s3:::<S3 BUCKET NAME>/*"
},
{
	"Sid": "GetCloudTrailObjects",
	"Effect": "Allow",
	"Principal": {
		"AWS": "<CROSS-ACCOUNT ROLE ARN>"
	},
	"Action": [
		"s3:ListBucket",
		"s3:GetBucket*"
	],
	"Resource": "arn:aws:s3:::<S3 BUCKET NAME>"
}
```


#### Running AWS CloudTrail Monitoring Utility
1. From CloudInsight user interface get your account id and environment id you want to setup to monitor your AWS CloudTrail. To get this information, login into CloudInsight, click on your user name in the top right corner and select 'Support'.  
2. Update ```~/.aws/credentials``` to contain a profiles that allow access to the account where AWS CloudTrail stores logs and account that generates CloudTrail logs  
3. Update ```config.json.template``` to include correct information for your deployment and save it as config.json
3.1 Below is the format of the configuration file
```
{
    "aws_account_id": "Put AWS Account ID where CloudTrail logs are originated from",
    "role": "<CROSS-ACCOUNT ROLE ARN>",
    "external_id": "<EXTERNAL ID>",
    "regions": {
        <REGION NAME>: {
            "type": "trail" | "queue",
            "trail" | "queue": <CLOUD TRAIL NAME> | <SQS QUEUE NAME>
            /* "bucket_region" property is only applicable for "queue" type. Of omitted, us-east-1 is used.
            "bucket_region": <Name of the region where bucket is located>
        },
        ...
    }
}  
Variables Description:
CROSS-ACCOUNT ROLE ARN - see Prerequisites 4.2
EXTERNAL ID - see Prerequisites 4.2
REGION NAME - Valid AWS CloudTrail Region name. See http://docs.aws.amazon.com/general/latest/gr/rande.html#ct_region
CLOUD TRAIL NAME - Name of the CloudTrail to setup monitoring for
SQS QUEUE NAME - Name (not arn) of the SQS QUEUE that subscribes to CloudTrail SNS Topic. SQS Queue must be in the same AWS Account as S3 bucket that receives CloudTrail logs.
```  
4. Run the utility. For the list of correct options execute:  
```$ ./ci_setup_cloudtrail --help```  
Here are a few examples on how to run ```./ci_setup_cloudtrail.py```  
4.1.  Setup CloudInsight backend to use queue and cross-account role specified in config.json for account id 123456
```
./ci_setup_cloudtrail.py -u someuser@acmecorp.com -p "Password1234$" -a 123456 -c config.json
```  
Example of config.json:
```
{
    "aws_account_id": "2222222222",
    "role": "arn:aws:iam::1111111111:role/CI_CloudTrail_Collection",
    "external_id": "EXTERNAL ID",
    "regions": {
    	"us-west-2": {
            "type": "queue",
            "queue": "outcomesbucket-12345"
        },
        "us-east-1": {
            "type": "queue",
            "queue": "outcomesbucket-12345"
        }
    }
}
```  
4.2.  Setup CloudInsight backend to use queue and cross-account role specified in config.json for account id 123456 in the UK region
```
./ci_setup_cloudtrail.py -u someuser@acmecorp.com -p "Password1234$" -a 123456 -c config.json -l uk
```  
4.3. Setup CloudInsight backend to monitor CloudTrail specified in config.json for account id 123456  
```
./ci_setup_cloudtrail.py -u someuser@acmecorp.com -p "Password1234$" -c config.json -s CloudTrailAccountProfile -P S3AccountProfile
```  
Where config.json is:
```
{
    "aws_account_id": "2222222222",
    "role": "arn:aws:iam::1111111111:role/CI_CloudTrail_Collection",
    "external_id": "EXTERNAL ID",
    "regions": {
    	"us-west-2": {
            "type": "trail",
            "trail": "CustomTrail"
        },
        "us-east-1": {
            "type": "trail",
            "trail": "Default"
        }
    }
}
```  
4.3. When you specify ```trail``` type in ```config.json```, the AWS CloudTrail Monitoring Utility performs the following:  
4.3.1 Discovers CloudTrail configuration in AWS account using profile specified by -s argument  
4.3.2 Creates SQS Queue to subscribe for SNS Topic Notifications in AWS account using profile specified by by the -P argument  
4.3.3 Subscribes newly created SQS Queue to receive SNS Topic Notifications  
5. The utility will print the S3 Bucket Policy statement that needs to be added to your S3 Bucket.
 
