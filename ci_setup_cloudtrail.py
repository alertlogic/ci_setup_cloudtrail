#!/usr/bin/env python

import re
import sys
import pprint
import json
import argparse
import boto.s3
import boto.sqs
import ssl

from boto.s3.connection import S3Connection
from argparse import RawTextHelpFormatter

from ci_api import authenticate, get_sources, create_source, get_credentials, create_credential


def main():
    parser = argparse.ArgumentParser("ci_setup_cloudtrail", description="Setup CloudInsight to monitor environment via AWS CloudTrail.", formatter_class=RawTextHelpFormatter)

    parser.add_argument("-u", "--user", metavar="user", help="CloudInsight's user name", required=True)
    parser.add_argument("-p", "--password", metavar="password", help="CloudInsight's password", required=True)
    parser.add_argument("-a", "--account", metavar="account_id", help="CloudInsight's account id", required=True)
    parser.add_argument("-e", "--environment", metavar="environment_id", help="CloudInsight's environment id", required=True)
    parser.add_argument("-c", "--config", metavar="config", help="Configuration file", required=True)
    parser.add_argument("-P", "--profile", metavar="profile", help="AWS SDK Profile name", required=True)
    args = parser.parse_args()
#    print args

    #
    # Load configuration file
    #
    with open(args.config) as data_file:    
        data = validate_config(json.load(data_file), args.profile)
    role_arn = data[u'role']
    external_id = data[u'external_id']

    config = (data)

    # Connect to CloudInsight
    #
    token = authenticate(args.user, args.password)
    print "Successfully logged in into CloudInsight."
#    print "Token:  %s" %  (token)

    #
    # Get CloudInsight Credential ID for the specified role_arn and external_id
    #
    credential_id = get_credential(token, args.account, role_arn, external_id)[u'credential'][u'id']

    for config in data[u'config']:
        setup_source(token, args.account, args.environment, data[u's3_bucket_region'], config[u'region'], config[u'sqs_queue'], credential_id)
    print "Successfully updated CloudInsight configuration."
    print_instructions(data)

def validate_config(data, profile):
    print "Validating configuration."
    if hasattr(ssl, '_create_unverified_context'):
        ssl._create_default_https_context = ssl._create_unverified_context

    # Validate s3 bucket and get the region name where it resides
    bucket_name = data[u'bucket']
    conn = profile and S3Connection(profile_name = profile) or S3Connection()
    bucket = conn.get_bucket(bucket_name)
    location = get_bucket_location(bucket.get_location())
    if u's3_bucket_region' not in data:
        data[u's3_bucket_region'] = location
    elif data[u's3_bucket_region'] != location:
        raise Exception("Bucket '%s' doesn't reside in '%s' region. Use '%s' in your configuration file" % \
                        (bucket_name, data[u's3_bucket_region'], location))

    # Validate SQS queues
    for config in data[u'config']:
        validate_sqs_queue(profile, config[u'region'], config[u'sqs_queue'])
    return data
  
def get_credential(token, account_id, arn, external_id):
    credentials = get_credentials(token, account_id)
    for credential in credentials:
        c = credential[u'credential']
        if (c[u'type'] == 'iam_role' and c[u'iam_role'][u'arn'] == arn):
            return credential

    return create_credential(token, account_id, arn, external_id)

def setup_source(token, account_id, environment_id, s3_bucket_region, region, sqs_queue_name, credential_id):
    print "Setting up source for: account_id: '%s', environment_id: '%s', region: '%s', sqs_queue: '%s', credential_id: '%s" % \
            (account_id, environment_id, region, sqs_queue_name, credential_id)

    source = get_source_config( \
                account_id, \
                environment_id, \
                region, \
                get_sources(token, account_id, environment_id, region))
    source[u'source'][u'config'][u's3aws'][u'credential'][u'id'] = credential_id    
    source[u'source'][u'config'][u's3aws'][u's3_bucket_region'] = s3_bucket_region
    source[u'source'][u'config'][u's3aws'][u'sqs_queue'] = sqs_queue_name
    create_source(token, account_id, source)

def get_source_config(account_id, environment_id, region, sources):
    for source in sources:
        config = source[u'source'][u'config']
        if (config[u'collection_method'] == 'api'and config[u'collection_type'] == 's3aws' and
            config[u's3aws'][u'aws_region'] == region and config[u's3aws'][u'sqs_queue']):
            return source

    return {
        u'source': {
            u'config': {
                u'collection_method': u'api',
                u'collection_type': u's3aws',
                u's3aws': {
                    u'aws_region': region,
                }
            },
            u'enabled': u'true',
            u'host': {u'id': environment_id},
            u'product_type': u'lm',
            u'type': u'api',
            u'environment': environment_id,
            u'name': u'"$outcomes-%s-%s' % (account_id, region)
        }
    }

def validate_sqs_queue(profile, region, sqs_queue_name):
    conn = profile and  boto.sqs.connect_to_region(region, profile_name = profile) or \
                        boto.sqs.connect_to_region(region) 
    sqs_queue = conn.get_queue(sqs_queue_name)
    if not sqs_queue:
        raise Exception("SQS Queue '%s' doesn't exist in '%s' region" % (sqs_queue_name, region))    

    statement = json.loads(sqs_queue.get_attributes()[u'Policy'])[u'Statement']
    for sid in statement:
        if u'Effect' in sid and sid[u'Effect'] == u'Allow' and \
                u'Action' in sid and sid[u'Action'] == u'SQS:SendMessage' and \
                u'Condition' in sid and u'ArnEquals' in sid[u'Condition'] and \
                u'aws:SourceArn' in sid[u'Condition'][u'ArnEquals']:
            arn = sid[u'Condition'][u'ArnEquals'][u'aws:SourceArn'].split(u':')
            if arn[2] == u'sns': return True
    print "Warning: Didn't detect if '%s' SQS Queue has permissions to allow SNS publishing. \
Follow instructions in http://docs.aws.amazon.com/sns/latest/dg/SendMessageToSQS.html#SendMessageToSQS.sqs.permissions to setup to give permission to the Amazon SNS topic to send messages to the Amazon SQS queue." % sqs_queue_name
 
def get_bucket_location(location):
    return location and location or u'us-east-1'

def print_instructions(data):
    s3_policy = {
        "Sid": "GetCloudTrailObjects",
        "Effect": "Allow",
        "Principal": {
            "AWS": data[u'role']
        },
        "Action": "s3:GetObject*",
        "Resource": "arn:aws:s3:::{}/*".format(data[u'bucket'])
    }
    print "Make sure to add the following statement to '{}' bucket policy".format(data[u'bucket'])
    print json.dumps(s3_policy, indent = 4)

if __name__ =='__main__':
    main()
