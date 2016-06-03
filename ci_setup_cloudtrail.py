#!/usr/bin/env python

import re
import sys
import pprint
import json
import argparse
import boto3
import boto3.session
import ssl

from argparse   import RawTextHelpFormatter
from ci_api     import CI_API
from aws_api    import get_cloud_trail_configuration, setup_subscriptions, validate_queue, get_account_id
from utils import Progress, Subprogress

def get_user_input():
    parser = argparse.ArgumentParser(
                "ci_setup_cloudtrail",
                description="Setup CloudInsight to monitor environment via AWS CloudTrail.",
                formatter_class=RawTextHelpFormatter)

    parser.add_argument("-u", "--user", metavar="user", help="CloudInsight's user name", required=True)
    parser.add_argument("-p", "--password", metavar="password", help="CloudInsight's password", required=True)
    parser.add_argument("-l", "--locality",
                        metavar="locality",
                        help="CloudInsight region. Choose from from 'us', 'uk'. Default is 'us'",
                        choices=['us', 'uk'],
                        required=False)
    parser.add_argument("-a", "--account", metavar="account_id", help="CloudInsight's account id", required=False)
    parser.add_argument("-e", "--environment", metavar="environment_id", help="CloudInsight's environment id", required=False)
    parser.add_argument("-c", "--config", metavar="config", help="Configuration file", required=True)
    parser.add_argument("-P", "--profile", metavar="profile", help="AWS SDK profile name for the AWS Account that owns AWS CloudTrail S3 bucket", required=False)
    parser.add_argument("-s", "--source-profile", metavar="source-profile", help="AWS SDK Account profile name for the AWS Account that generates AWS CloudTrail logs", required=False)
    return parser.parse_args()


def main():
    args = get_user_input()

    targetAccountSession = args.profile and boto3.session.Session(profile_name = args.profile) or None
    sourceAccountSession = args.source_profile and boto3.session.Session(profile_name = args.source_profile) or None

    #
    # Connect to CloudInsight
    #
    ci = CI_API(args.user, args.password, account_id = args.account, locality = args.locality)

    print "Successfully logged in into CloudInsight. Account: %s(%s), User: %s" % \
            (ci.auth_account_name, ci.auth_account_id, ci.auth_user_name)
    #
    # Load configuration file
    #
    config = {}
    environments = []
    with open(args.config) as data_file:    
        config = json.load(data_file)
        if u'role' not in config:
            raise Exception("Missing 'role' attribute in '%s' configuration file" % (args.config))
        if u'external_id' not in config:
            raise Exception("Missing 'external_id' attribute in '%s' configuration file" % (args.config))
        if u'trails' not in config and u'regions' not in config :
            raise Exception("Missing 'trails' and 'regions' configuration in '%s' configuration file" % (args.config))

        role_arn = config[u'role']
        external_id = config[u'external_id']

        if u'environments' in config:
            environments = config[u'environments']
        elif u'aws_account_id' in config:
            environments = ci.get_environments(config[u'aws_account_id'])

    #
    # Get CloudInsight Credential ID for the specified role
    #
    credential_id = get_credential(ci, role_arn, external_id)[u'credential'][u'id']
    print "Obtained credential id for '%s' role" % (role_arn)

    #
    # Get sources for environments specified in the configuration file
    #
    sources = []
    trails = {}
    progress = Progress(
                len(config[u'regions']),
                "Validating configuration.\t\t\t\t\t\t\t\t\t\t")
    for region_name, region_config in config[u'regions'].iteritems():
        progress.report()
        if region_config[u'type'] == u'queue':
            if not u'queue' in region_config:
                raise Exception("Invalid config file. 'queue' property is missing for '%s' region" % region_name)

            if targetAccountSession and not validate_queue(region_name, region_config[u'queue'], targetAccountSession):
                raise Exception("Invalid config file. '%s' queue doesn't exist in '%s' region in '%s' AWS Account." %\
                               (region_config[u'queue'], region_name, get_account_id(targetAccountSession) ) )

            bucket_region = u'bucket_region' in region_config and region_config[u'bucket_region'] or u'us-east-1'
            for environment_id in environments:
                result = ci.get_sources(environment_id = environment_id, region = region_name)
                sources.append(update_source_config(
                        len(result) and result[0] or None,
                        ci.account_id,
                        environment_id,
                        region_name,
                        credential_id = credential_id,
                        bucket_region = bucket_region,
                        queue = region_config[u'queue']))
        elif region_config[u'type'] == u'trail':
            if u'trail' not in region_config or not region_config[u'trail']:
                raise Exception("Invalid config file. 'trail' property is missing '%s' region" % region_name)
            
            trail = get_cloud_trail_configuration(
                                    region_name,
                                    region_config[u'trail'], 
                                    sourceAccountSession,
                                    targetAccountSession)
            if trail:
                 trails[region_name] = trail
    progress.done()

    #
    # Setup CloudTrail subscriptions
    #
    for environment_id in environments:
        trails_configuration = setup_subscriptions(
                                    args.account,
                                    environment_id,
                                    trails,
                                    sourceAccountSession,
                                    targetAccountSession)

        for region_name, trail_configuration in trails_configuration.iteritems():
                result = ci.get_sources(environment = environment_id, region = region_name)
                sources.append(update_source_config(
                        len(result) and result[0] or None,
                        ci.account_id,
                        environment_id,
                        region_name,
                        credential_id = credential_id,
                        bucket_region = trail_configuration[u'bucket_region'],
                        queue = trail_configuration[u'sqs_queue_name']))

    #
    # Create CloudInsight sources
    #
    for source in sources:
        print "Updating '%s' source in '%s' environment." %\
              (source[u'source'][u'name'], source[u'source'][u'environment'])
        ci.create_source(source)
    print "Successfully updated CloudInsight configuration."
    print_instructions(role_arn)

def get_credential(ci, arn, external_id):
    credentials = ci.get_credentials()
    for credential in credentials:
        c = credential[u'credential']
        if (c[u'type'] == 'iam_role' and c[u'iam_role'][u'arn'] == arn):
            return credential

    return ci.create_credential(arn, external_id)

def update_source_config(source, account_id, environment_id, region, **kwargs):
    if not source: source = new_source_config(account_id, environment_id, region)
    if 'bucket_region' in kwargs and kwargs['bucket_region']:
        source[u'source'][u'config'][u's3aws'][u's3_bucket_region'] = kwargs['bucket_region']
    if 'queue' in kwargs and kwargs['queue']:
        source[u'source'][u'config'][u's3aws'][u'sqs_queue'] = kwargs['queue']
    if 'credential_id' in kwargs and kwargs['credential_id']:
        source[u'source'][u'config'][u's3aws'][u'credential'][u'id'] = kwargs['credential_id']
    return source

def new_source_config(account_id, environment_id, region):
    return {
        u'source': {
            u'config': {
                u'collection_method': u'api',
                u'collection_type': u's3aws',
                u's3aws': {
                    u'aws_region': region,
                    u'credential': {
                        u'id': ''
                    },
                    u's3_bucket_region': '',
                    u'sqs_queue': ''
                }
            },
            u'enabled': True,
            u'product_type': u'lm',
            u'type': u'api',
            u'environment': environment_id,
            u'name': u'$outcomes-%s-%s-%s' % (account_id, region, environment_id)
        }
    }
   
def print_instructions(role_arn):
    s3_policy = [
        {
            "Sid": "GetCloudTrailObjects",
            "Effect": "Allow",
            "Principal": {
                "AWS": "{}".format(role_arn)
            },
            "Action": [
                "s3:GetObjectVersionAcl",
                "s3:GetObject",
                "s3:GetObjectAcl"
            ],
            "Resource": "arn:aws:s3:::<bucket_name>/*"
        },
        {
            "Sid": "GetCloudTrailObjects",
            "Effect": "Allow",
            "Principal": {
                "AWS": "{}".format(role_arn)
            },
            "Action": [
                "s3:ListBucket",
                "s3:GetBucket*"
            ],
            "Resource": "arn:aws:s3:::<bucket_name>"
        }
    ]
    #print "Make sure to add the following statement to '{}' bucket policy".format(data[u'bucket'])
    print "Make sure to add the following statement to S3 bucket policy."
    print json.dumps(s3_policy, indent = 4)

if __name__ =='__main__':
    main()
