# Configuring CloudInsight AWS CloudTrail Monitoring
## Setup
### Mac OS X Installation Requirements
```ci_setup_cloudtrail``` requires Python 2.7 or higher.

#### Install Python

```$ brew install python```

**Note:** The latest version of Mac OS X, El Capitan, comes with Python 2.7 out of the box. 

#### Install the latest version of boto
```$ pip install boto```

If you already have boto installed, make sure to upgrade it to the latest version.

```$ pip install --upgrade boto```

**Note:** Homebrew installs ```pip``` for you.


### Linux Installation Requirements	

#### Install Python
Install python package using your OS package installation system (dpkg or rpm). Make sure the version of python is 2.7 or higher.

**Note:** The latest versions of CentOS, Fedora, Redhat Enterprise (RHEL) and Ubuntu come with Python 2.7 out of the box.

#### Install the latest version of boto
```$ pip install boto```

If you already have boto installed, make sure to upgrade it to the latest version.

```$ pip install --upgrade boto```

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
2. Switch to an account that owns S3 bucket where AWS CloudTrail logs are stored. 
3. Create SQS Queues for each region you want CloudInsight to monitor and subscribe to the SNS Topic used to receive AWS CloudTrail notifications. Follow detailed instructions see: http://docs.aws.amazon.com/sns/latest/dg/SendMessageToSQS.html   
4. Create a cross-account role to give CloudInsight permission to access AWS CloudTrail logs.    
4.1. Create IAM Policy to be used by cross-account role. Use the policy document below and make sure to substitute strings in ```<>``` with your account's values.  
```  
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GetCloudTrailData",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetBucket*",
                "s3:GetObjectAcl",
                "s3:GetObjectVersionAcl"
            ],  
            "Resource": "<YOUR S3 BUCKET ARN>*"
        },
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

#### Running AWS CloudTrail Monitoring Utility
1. From CloudInsight user interface get your account id and environment id you want to setup to monitor your AWS CloudTrail. To get this information, login into CloudInsight, click on your user name in the top right corner and select 'Support'.  
2. Update ```~/.aws/credentials``` to contain a profile that allows access to the account where AWS CloudTrail stores logs  
3. Update ```config.json.template``` to include correct information for your deployment and save it as config.json
4. Run the utility. For the list of correct options execute:  
```$ ./ci_setup_cloudtrail --help```  
Here is an example with command line options specied:  
```./ci_setup_cloudtrail.py -u someuser@acmecorp.com -p "Password1234$" -a 99999999 -e "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -c config.json -P production_profile``` 

 
