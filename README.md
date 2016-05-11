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
Download ```ci_setup_cloudtrail``` utility

```git clone git@github.com:alertlogic/ci_setup_cloudtrail.git ci_setup_cloudtrail```

Give yourself permission to exectute ```ci_setup_cloudtrail.py```

```
$ cd ci_setup_cloudtrail 
$ chmod 755 ci_setup_cloudtrail.py
```

### Run CloudInsight AWS CloudTrail Monitoring Utility
#### Prerequisites
1. Create a cross-account role to give CloudInsight permission to access AWS CloudTrail logs  
1.1. Create IAM Policy to be used by cross-account role using the policy document below:  
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
1.2. Create a cross-account role  
1.2.1. CloudInsight AWS Account ID: 733251395267  
1.2.2. Pick Extrenal ID  
1.2.3. Choose policy created in step 1.1  
