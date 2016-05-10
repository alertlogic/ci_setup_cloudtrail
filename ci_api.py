import ssl
import urllib2
import base64
import json

from urllib2 import Request, urlopen, URLError, HTTPError

################################################################

DEBUG = False

def get_api_endpoint():
    if DEBUG: return 'api.product.dev.alertlogic.com'
    else: return 'api.cloudinsight.alertlogic.com'

################################################################

def get_sources(token, account_id, environment_id, region):
    params = {
        "headers": {
            "x-aims-auth-token": token
        },
        "url": 'https://%s/sources/v1/%s/sources?source.config.aws.defender_support=!true&source.type=api&source.config.s3aws.aws_region=%s' % \
                (get_api_endpoint(), account_id, region)
    }
    sources = json.loads(http_operation(params))[u'sources']

    # filter out only sources for the specified environment
    return [ source for source in sources if source[u'source'][u'environment'] == environment_id ]

def create_source(token, account_id, source):
    params = {
        "headers": {
            "x-aims-auth-token": token
        },
        "url": 'https://%s/sources/v1/%s/sources' % (get_api_endpoint(), account_id)
    }
    http_operation(params, source)

def get_credentials(token, account_id):
    params = {
        "headers": {
            "x-aims-auth-token": token
        },
        "url": 'https://%s/sources/v1/%s/credentials' % (get_api_endpoint(), account_id)
    }
    return json.loads(http_operation(params))[u'credentials']

def create_credential(token, account_id, arn, external_id):
    print "Creating credential object. Account: '%s', Role: '%s'" % (account_id, arn)
    params = {
        "headers": {
            "x-aims-auth-token": token,
            "Content-Type": "application/json"
        },
        "url": 'https://%s/sources/v1/%s/credentials' % (get_api_endpoint(), account_id)
    }
    data = {
        "credential": {
            "name": "CrossAccountCloudTrailRole",
            "type": "iam_role",
            "iam_role": {
                "arn": arn,
                "external_id": external_id
            }
        }
    }
    return json.loads(http_operation(params, data))

def authenticate(username, password):
    try:
        x = ssl.PROTOCOL_TLSv1_2
    except AttributeError:
        # TLSv1.2 is not supported in this version of python.  Please upgrade to the latest version.
        # If you are running Mac OS X 10.10, you can use homebrew to install a supported version of
        # python by running 'brew install python'
        raise Exception("TLSv1.2 is required.  It is not supported in this version of python.  Hint: If you're on OS X 10.10, install homebrew and run 'brew install python'")

    auth_header = "Basic %s" % base64.b64encode("%s:%s" % (username, password))
    params = {
        "headers" : {
            "Authorization": auth_header
        },
        "url": 'https://%s/aims/v1/authenticate' % (get_api_endpoint())
    }

    #perform authentication
    datas = ''
    request = Request(params["url"], datas, params["headers"])
    try:
        response = urlopen(request)
    except HTTPError as e:
        print 'The server couldn\'t fulfill the request.'
        print 'Error code: ', e.code
        raise e
    except URLError as e:
        print 'We failed to reach a server.'
        print 'Reason: ', e.reason
        raise e
    else:
        return json.loads(response.read())[u'authentication'][u'token']

def http_operation(params, data = None):
    request = Request(params["url"], (None if not data else  json.dumps(data)), params["headers"])
    try:
        response = urlopen(request)
    except HTTPError as e:
        print 'The server couldn\'t fulfill the request.'
        print 'Error code: ', e.code
        raise e
    except URLError as e:
        print 'We failed to reach a server.'
        print 'Reason: ', e.reason
        raise e
    else:
        return response.read()

def get_account_id(token):
    return json.loads(base64.b64decode(token.split('.')[1]))


