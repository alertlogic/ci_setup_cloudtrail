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
from ci_api     import authenticate, get_sources, create_source, get_credentials, create_credential
from aws_api    import get_cloud_trail_configuration
from aws_api    import setup_subscriptions

def get_user_input():
    parser = argparse.ArgumentParser(
                "ci_setup_cloudtrail",
                description="Setup CloudInsight to monitor environment via AWS CloudTrail.",
                formatter_class=RawTextHelpFormatter)

    parser.add_argument("-u", "--user", metavar="user", help="CloudInsight's user name", required=True)
    parser.add_argument("-p", "--password", metavar="password", help="CloudInsight's password", required=True)
    parser.add_argument("-a", "--account", metavar="account_id", help="CloudInsight's account id", required=True)
    parser.add_argument("-e", "--environment", metavar="environment_id", help="CloudInsight's environment id", required=True)
    parser.add_argument("-c", "--config", metavar="config", help="Configuration file", required=True)
    parser.add_argument("-P", "--profile", metavar="profile", help="AWS SDK Profile name", required=True)
    parser.add_argument("-s", "--source-profile", metavar="source-profile", help="AWS SDK Primary Account Profile Name", required=False)
    return parser.parse_args()


def main():
    args = get_user_input()

    targetAccountSession = boto3.session.Session(profile_name = args.profile)
    sourceAccountSession = args.source_profile and boto3.session.Session(profile_name = args.source_profile) or None

    #
    # Connect to CloudInsight
    #
    token = authenticate(args.user, args.password)
    print "Successfully logged in into CloudInsight."
    # print "Token:  %s" %  (token)

    #
    # Load configuration file
    #
    with open(args.config) as data_file:    
        config = json.load(data_file)
        if u'role' not in config:
            raise Exception("Missing 'role' attribute in '%s' configuration file" % (args.config))
        if u'external_id' not in config:
            raise Exception("Missing 'external_id' attribute in '%s' configuration file" % (args.config))
        if u'trails' not in config:
            raise Exception("Missing 'trails' configuration in '%s' configuration file" % (args.config))

        role_arn = config[u'role']
        external_id = config[u'external_id']
        trails_configuration = get_cloud_trail_configuration(
                                config[u'trails'],
                                sourceAccountSession,
                                targetAccountSession)
        if not trails_configuration[u'valid_trails']:
            raise Exception("No valid trails configurations were found in '%s' configuration file" % (args.config))

    #
    # Get CloudInsight Credential ID for the specified role
    #
    credential_id = get_credential(token, args.account, role_arn, external_id)[u'credential'][u'id']
    print "Obtained credential id for '%s' role" % (role_arn)

    #
    # Setup CloudTrail subscriptions
    #
    trails_configuration = setup_subscriptions(
                                args.account,
                                args.environment,
                                trails_configuration,
                                sourceAccountSession,
                                targetAccountSession)

    #
    # Create CloudInsight sources
    #
    for region, trail in trails_configuration[u'valid_trails'].items():
        setup_source(
            token, 
            args.account, 
            args.environment, 
            credential_id,
            trail)
    print "Successfully updated CloudInsight configuration."

def get_credential(token, account_id, arn, external_id):
    credentials = get_credentials(token, account_id)
    for credential in credentials:
        c = credential[u'credential']
        if (c[u'type'] == 'iam_role' and c[u'iam_role'][u'arn'] == arn):
            return credential

    return create_credential(token, account_id, arn, external_id)

def setup_source(token, account_id, environment_id, credential_id, trail):
    source = get_source_config( \
                account_id, \
                environment_id, \
                trail[u'region'], \
                get_sources(token, account_id, environment_id, trail[u'region']))
    source[u'source'][u'config'][u's3aws'][u'credential'][u'id'] = credential_id    
    source[u'source'][u'config'][u's3aws'][u's3_bucket_region'] = trail[u'bucket_region']
    source[u'source'][u'config'][u's3aws'][u'sqs_queue'] = trail[u'sqs_queue_name']
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
            u'name': u'$outcomes-%s-%s' % (account_id, region)
        }
    }

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
