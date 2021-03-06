
import json
import boto3
import ssl

from utils import Progress, Subprogress

def get_cloud_trail_configuration(region_name, trail_name, sourceAccountSession, targetAccountSession):
    if not sourceAccountSession or not targetAccountSession:
        print "WARNING. Invalid configuration provided for '%s' region. Skipping..." % region_name
        return None

    source_account_id = get_account_id(sourceAccountSession)
    target_account_id = get_account_id(targetAccountSession)
    trail = sourceAccountSession.client(
            'cloudtrail', 
            region_name = region_name).describe_trails(trailNameList=[trail_name])[u'trailList']
    if not trail:
        return None

    # Get bucket
    bucket_name = trail[0][u'S3BucketName']
    try:
        location = get_bucket_location(targetAccountSession.client('s3').get_bucket_location(Bucket = bucket_name))
    except Exception as e:
        if e.response['Error']['Code']:
            return None
            # This bucket doesn't belong to the 'target_account_id'
#            invalid_trails[region] = make_trail_error(
#                    trails_list[region],
#                    "Bucket doesn't belong to %s" % (target_account_id))
#                continue
        else:
            return None

    # Make sure CloudTrail has SNS Topic
    if u'SnsTopicARN' not in trail[0]:
        return None

    return get_region_config(location, trail[0])

def setup_subscriptions(account_id, environment_id, trails_configuration, sourceAccountSession, targetAccountSession):
    prefix = "Setting up CloudTrails subscriptions for environment %s:" % environment_id
    regions = trails_configuration.keys()
    if not len(regions): return trails_configuration

    progress = Progress(
                len(regions),
                prefix + "\t\t")

    for region in regions:
        trail = trails_configuration.pop(region)
        try:
            trails_configuration[region] = aws_setup_subscription(
                            account_id,
                            environment_id,
                            trail,
                            sourceAccountSession,
                            targetAccountSession,
                            progress)
        except Exception as e:
            print "Error: %s" % (e)
        #    details = e.args[0]
            # trails_configuration[u'invalid_trails'][region] = details['reason']
        progress.report()
    progress.done()
    return trails_configuration

def aws_setup_subscription(account_id, environment_id, trail, sourceAccountSession, targetAccountSession, progress):
    subprogress = Subprogress(progress, 5)

    source_account_id = get_account_id_from_arn(sourceAccountSession.client('iam').get_user()[u'User'][u'Arn'])
    target_account_id = get_account_id_from_arn(targetAccountSession.client('iam').get_user()[u'User'][u'Arn'])

    topic_account_id = get_account_id_from_arn(trail[u'topic_arn'])
    topic_region = get_region_from_arn(trail[u'topic_arn'])

    if topic_account_id == source_account_id:
        sns = sourceAccountSession.client('sns', region_name = topic_region)
    elif topic_account_id == target_account_id:
        sns = targetAccountSession.client('sns', region_name = topic_region)
    else:
        message = "Topic '%s' doesn't belong to either '%s' or '%s' accounts." % \
                  (trail[u'topic_arn'], source_account_id, target_account_id)
        raise Exception(make_trail_error(topic_region, message))

    #
    # Create SQS Queue in the target account
    #
    sqs = targetAccountSession.client('sqs', region_name = trail[u'region'])
    queue_name = "outcomesbucket-%s-%s" % (account_id, environment_id)
    try:
        queue_url = sqs.get_queue_url(QueueName = queue_name)[u'QueueUrl']
    except Exception as e:
        if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
            # Queue doesn't exist. Create it.
            queue_url = sqs.create_queue(QueueName = queue_name)[u'QueueUrl']
        else:
            print e.response['Error']
            message = "Failed to get '%s' queue in '%s' region. Error: %s" % \
                      (queue_name, trail[u'region'], e.response['Error']['Code'])
            raise Exception(make_trail_error(trail[u'region'], message))
    subprogress.report()

    #
    # Subscribe queue to the SNS Topic
    #
    try:
        attributes = sqs.get_queue_attributes(
                        QueueUrl = queue_url,
                        AttributeNames = ['QueueArn', 'Policy'])[u'Attributes']
        subprogress.report()

        trail[u'sqs_queue_arn'] = attributes['QueueArn']
        trail[u'sqs_queue_name'] = queue_name
        policy = 'Policy' in attributes and attributes['Policy'] or None
        
        if not validate_queue_policy(account_id, environment_id, trail, policy):
            sqs.set_queue_attributes(
                QueueUrl = queue_url,
                Attributes={
                    'Policy': get_queue_policy(account_id, environment_id, trail, policy)
                })
            subprogress.report()

        #
        # If SQS Queue already subscribed to SNS Topic, do nothing.
        #
        if get_topic_queue_subscription(sns, trail[u'topic_arn'], trail[u'sqs_queue_arn']):
            subprogress.done()
            return trail

        sns.subscribe(
            TopicArn = trail[u'topic_arn'],
            Protocol = 'sqs',
            Endpoint = trail[u'sqs_queue_arn'])
        subprogress.report()

        if target_account_id != get_account_id_from_arn(trail[u'topic_arn']):
            #
            # SNS Topic lives in another account. Confirm subscription.
            #
            response = sns.confirm_subscription( 
                Token = get_token(sqs.receive_message(
                    QueueUrl = queue_url,
                    MaxNumberOfMessages = 1,
                    WaitTimeSeconds = 5)),
                TopicArn = trail[u'topic_arn'])
            subprogress.report()

    except Exception as e:
        print e
        message = "Failed to subscribe '%s' queue to '%s' topic in '%s' region. Error: %s" % \
                  (queue_url, trail[u'topic_arn'], trail[u'region'], e.response['Error'])
        raise Exception(make_trail_error(trail[u'region'], message))
    
    subprogress.done()
    return trail

def validate_queue(region, queue, targetAccountSession):
    sqs = targetAccountSession.client('sqs', region_name = region)
    try:
        queue_url = sqs.get_queue_url(QueueName = queue)[u'QueueUrl']
        return True
    except Exception as e:
        if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
            # Queue doesn't exist. Create it.
            return False
        else:
            print e.response['Error']
            message = "Failed to get '%s' queue in '%s' region. Error: %s" % \
                      (queue_name, trail[u'region'], e.response['Error']['Code'])
            raise Exception(make_trail_error(trail[u'region'], message))

def get_account_id(session):
    return get_account_id_from_arn(session.client('iam').get_user()[u'User'][u'Arn'])

def get_trails_list(trails, session):
    result = {}
    for trail in trails:
        if trail[u'regions'] == 'all':
            regions = session.get_available_regions('cloudtrail')
        else:
            regions = trail[u'regions']

        for region in regions:
            result[region] = trail[u'name']
    return result


def get_bucket_location(location):
    constraint = location['LocationConstraint']
    return constraint and constraint or u'us-east-1'

def get_region_config(location, trail):
    if u'TrailARN' not in trail or not trail[u'TrailARN']:
        raise Exception("ERROR: SNS Topic Configuration is missing for '%s' CloudTrail in '%s' region" % (trail[u'Name'], trail[u'HomeRegion']))

    return {
        u'region':      trail[u'HomeRegion'],
        u'bucket_region': location,
        u'bucket':      trail[u'S3BucketName'],
        u'topic_arn':   trail[u'SnsTopicARN']
    }

def make_trail_error(name, reason):
    return {
        u'name': name,
        u'reason': reason
    }

def get_name_from_arn(arn):
    return arn.split(':')[5]

def get_account_id_from_arn(arn):
    return arn.split(':')[4]

def get_region_from_arn(arn):
    return arn.split(':')[3]

def get_token(message):
    return json.loads(message[u'Messages'][0][u'Body'])[u'Token']

def get_queue_policy_label(account_id, environment_id, topic_arn):
    return "outcomesbucket-%s-%s-%s-SendMessage" % \
            (account_id, environment_id, get_name_from_arn(topic_arn))

def validate_queue_policy(account_id, environment_id, trail, policy):
    if not policy: return False

    label = get_queue_policy_label(account_id, environment_id, trail[u'topic_arn'])
    statement = json.loads(policy)['Statement']
    for sid in statement:
        if sid[u'Sid'] == label: 
            return True    
    return False 

def get_queue_policy(account_id, environment_id, trail, policy):
    if not policy:
        policy_json = {
            u'Version': "2012-10-17",
            u'Id': "{}/SQSDefaultPolicy".format(trail[u'sqs_queue_arn']),
            u'Statement': [] 
        }
    else:
        policy_json = json.loads(policy)
    
    statement = policy_json[u'Statement']
    statement.append({
        u'Sid': get_queue_policy_label(account_id, environment_id, trail[u'topic_arn']),
        u'Effect': "Allow",
        u'Principal': {
            u'AWS': "*"
        },
        u'Action': "SQS:SendMessage",
        u'Resource': trail[u'sqs_queue_arn'],
        u'Condition': {
            u'ArnEquals': {
                'aws:SourceArn': trail[u'topic_arn']
            }
        }
    })
    policy_json['Statement'] = statement
    return json.dumps(policy_json)

def get_topic_queue_subscription(sns, topic_arn, sqs_queue_arn):
    response = sns.list_subscriptions_by_topic(TopicArn = topic_arn)
    while True:
        for subscription in response[u'Subscriptions']:
            if subscription[u'Endpoint'] == sqs_queue_arn: return subscription

        if u'NextToken' not in response: break

        response = sns.list_subscriptions_by_topic(
                    TopicArn = topic_arn,
                    NextToken = response[u'NextToken'])
    return None

