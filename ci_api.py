import ssl
import urllib2
import base64
import json

from urllib2 import Request, urlopen, URLError, HTTPError

################################################################

def get_api_endpoint(locality = 'us'):
    return {
        'DEBUG': 'api.product.dev.alertlogic.com',
        'us': 'api.cloudinsight.alertlogic.com',
        'uk': 'api.cloudinsight.alertlogic.co.uk',
    }.get(locality, 'api.cloudinsight.alertlogic.com') 

################################################################

class CI_API:
    api_endpoint        = get_api_endpoint()
    token               = None
    account_id          = None
    auth_account_id     = None
    auth_account_name   = None
    auth_user_name      = None
    def __init__(self, user, password, **kwargs):
        if 'locality' in kwargs and kwargs['locality']:
            self.api_endpoint = get_api_endpoint(kwargs['locality'])

        auth_info = authenticate(self.api_endpoint, user, password)
        self.token = auth_info[u'token']
        if 'account_id' in kwargs and kwargs['account_id']:
            self.account_id = kwargs['account_id']
        else:
            self.account_id = auth_info[u'account'][u'id']
            
        self.auth_account_name  = auth_info[u'account'][u'name']
        self.auth_account_id    = auth_info[u'account'][u'id']
        self.auth_user_name     = auth_info[u'user']['name']

    def get_environments(self, aws_account_id):
        url = 'https://%s/sources/v1/%s/sources?source.config.aws.account_id=%s' %\
              (self.api_endpoint, self.account_id, aws_account_id)
        params = {
            "headers": {
                "x-aims-auth-token": self.token
            },
            "url": url
        }
        return [source[u'source'][u'id'] for source in json.loads(http_operation(params))[u'sources']]

    def get_sources(self, **kwargs):
        url_args = []
        sources = []
        url = 'https://%s/sources/v1/%s/sources' % (self.api_endpoint, self.account_id)
       
        if 'region' in kwargs:
            url_args.append('source.config.s3aws.aws_region=%s' % kwargs['region'])

        if 'environment_id' in kwargs and kwargs['environment_id']:
            url_args.append('source.environment=%s' % kwargs['environment_id'])
     
        params = {
            'headers': {
                'x-aims-auth-token': self.token
            },
            'url': len(url_args) and url + '?' + '&'.join(url_args) or url
        }
        return json.loads(http_operation(params))[u'sources']

    def create_source(self, source):
        params = {
            "headers": {
                "x-aims-auth-token": self.token
            },
            "url": 'https://%s/sources/v1/%s/sources' % (self.api_endpoint, self.account_id)
        }
        http_operation(params, source)

    def get_credentials(self):
        params = {
            "headers": {
                "x-aims-auth-token": self.token
            },
            "url": 'https://%s/sources/v1/%s/credentials' % (self.api_endpoint, self.account_id)
        }
        return json.loads(http_operation(params))[u'credentials']

    def create_credential(self, arn, external_id):
        print "Creating credential object. Account: '%s', Role: '%s'" % (self.account_id, arn)
        params = {
            "headers": {
                "x-aims-auth-token": self.token,
                "Content-Type": "application/json"
            },
            "url": 'https://%s/sources/v1/%s/credentials' % (self.api_endpoint, self.account_id)
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

def authenticate(api_endpoint, username, password):
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
        "url": 'https://%s/aims/v1/authenticate' % api_endpoint
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
        return json.loads(response.read())[u'authentication']

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


