from operator import eq
import os
import json
import requests
from requests.auth import HTTPBasicAuth
from paramiko import AuthenticationException, AutoAddPolicy, BadHostKeyException, SSHException
from paramiko import SSHClient
from scp import SCPClient
from scp import SCPException


bigip_ip='10.1.1.151'
bigip='https://{0}'.format(bigip_ip)

library = {'auth-token':'/mgmt/shared/authn/login',
           'mng-tokens':'/mgmt/shared/authz/tokens',
           'pass-policy':'/mgmt/tm/auth/password-policy',
           'pass-change':'/mgmt/tm/auth/user/',
           'get-version':'/mgmt/tm/sys/version',
           'file-xfr':'/mgmt/shared/file-transfer/uploads/',
           'mgmt-tasks':'/mgmt/shared/iapp/package-management-tasks',
           'do-info':'/mgmt/shared/declarative-onboarding/info',
           'as3-info':'/mgmt/shared/appsvcs/info',
           'do-upload':'/mgmt/shared/declarative-onboarding/',
           'do-tasks':'/mgmt/shared/declarative-onboarding/task/',
           'as3-upload':'/mgmt/shared/appsvcs/declare?async=true',
           'as3-tasks':'/mgmt/shared/appsvcs/task/',
           'bash':'/mgmt/tm/util/bash',
}

# Some simple exceptions
class ValidationError(Exception):
    pass
    #def __init__(self, message, errors):
    #    super().__init__(message)
    #    self.errors = errors

class InvalidURL(Exception):
    pass

class SendRequestFailure(Exception):
    pass

def sendRequest(url, session=None, data=None):
    
    if not url:
        raise InvalidURL("The url {0} is invalid".format(url) )

    try:
        error_message = ""
        if None == session:
            session = requests.Session()
            session.verify = False

        # Send request and then raise exceptions for 4xx and 5xx issues
        #response = session.post(url, json=data) # this doesn't work for uploads...
        response = session.post(url, data)
        response.raise_for_status()

    except requests.exceptions.HTTPError as e_http:
        # Handle 4xx and 5xx errors here.  Common 4xx and 5xx REST errors here
        if response.status_code == 400:
            m = "400 Bad request.  The url is wrong or malformed"
        elif response.status_code == 401:
            m = "401 Unauthorized.  The client is not authorized for this action or auth token is expired"
        elif response.status_code == 404:
            m = "404 Not Found.  The server was unable to find the requested resource"
        elif response.status_code == 415:
            m = "415 Unsupported media type.  The request data format is not supported by the server"
        elif response.status_code == 422:
            m = "422 Unprocessable Entity.  The request data was properly formatted but contained invalid or missing data"
        elif response.status_code == 500:
            m = "500 Internal Server Error.  The server threw an error while processing the request"
        else:
            m = "{0}.  Uncommon REST/HTTP error".format(response.status_code)

        error_message = '{0}:\t{1}.  Additional Data:\t{2}'.format('HTTPError', m, e_http)

    except requests.exceptions.TooManyRedirects as e_redir:
        # Handle excessive 3xx errors here
        # test by adding allow_redirects=False and going to a site with a redirects
        error_message = '{0}:  {1}'.format('TooManyRedirects', e_redir)

    except requests.exceptions.ConnectionError as e_conn:
        # Handle connection errors here
        # test by adding allow_redirects=False and do http req to https site
        error_message = '{0}:  {1}'.format('ConnectionError', e_conn)

    except requests.exceptions.Timeout as e_tout:
        # Handle timeout errors here
        # Test by adding timeout=0.0001 
        error_message = '{0}:  {1}'.format('Timeout', e_tout)    

    except requests.exceptions.RequestException as e_general:
        # Handle ambiguous exceptions while handling request
        error_message = '{0}:  {1}'.format('RequestException', e_general)

    else:
        return response.json()

    finally:
        if error_message:
            raise SendRequestFailure(error_message)

    return

# Get an auth token
url = "{0}{1}".format(bigip, (library['auth-token']))
hdrs = {'content-type':'application/json'}
body = {'username':'admin', 'password':'admin', 'loginProviderName':'tmos'}
response = requests.post(url, json=body, headers=hdrs, verify=False )
token = response.json()['token']['token']

""" 
# Use an auth token
url = "{0}{1}/{2}".format(bigip, (library['mng-tokens']), token )
hdrs = {'X-F5-Auth-Token' : token}

response = requests.get(url, headers=hdrs, verify=False )
out = response.json()
print(out )
 """
# more robust example:
# handles:
#   3xx - Redirection
#   4xx - Client Error
#   5xx - Server Error
# ignores:
#   1xx - Informational
# You process
#   2xx - Successful

#Try: This block will test the excepted error to occur
#Except:  Here you can handle the error
#Else: If there is no exception then this block will be executed
#Finally: Finally block always gets executed either exception is generated or not

try:
    error_message = ""
    url = '{0}{1}'.format(bigip, library['get-version'])
    session = requests.Session()
    session.headers.update({'X-F5-Auth-Token' : token})
    session.verify = False

    # Send request and then raise exceptions for 4xx and 5xx issues
    response = session.get(url)
    response.raise_for_status()

except requests.exceptions.HTTPError as e_http:
    # Handle 4xx and 5xx errors here.  Common 4xx and 5xx REST errors here
    if response.status_code == 400:
        m = "400 Bad request.  The url is wrong or malformed"
    elif response.status_code == 401:
        m = "401 Unauthorized.  The client is not authorized for this action or auth token is expired"
    elif response.status_code == 404:
        m = "404 Not Found.  The server was unable to find the requested resource"
    elif response.status_code == 415:
        m = "415 Unsupported media type.  The request data format is not supported by the server"
    elif response.status_code == 422:
        m = "422 Unprocessable Entity.  The request data was properly formatted but contained invalid or missing data"
    elif response.status_code == 500:
        m = "500 Internal Server Error.  The server threw an error while processing the request"
    else:
        m = "{0}.  Uncommon REST/HTTP error".format(response.status_code)

    error_message = '{0}:\t{1}.  Additional Data:\t{2}'.format('HTTPError', m, e_http)

except requests.exceptions.TooManyRedirects as e_redir:
    # Handle excessive 3xx errors here
    # test by adding allow_redirects=False and going to a site with a redirects
    error_message = '{0}:  {1}'.format('TooManyRedirects', e_redir)

except requests.exceptions.ConnectionError as e_conn:
    # Handle connection errors here
    # test by adding allow_redirects=False and do http req to https site
    error_message = '{0}:  {1}'.format('ConnectionError', e_conn)

except requests.exceptions.Timeout as e_tout:
    # Handle timeout errors here
    # Test by adding timeout=0.0001 
    error_message = '{0}:  {1}'.format('Timeout', e_tout)    

except requests.exceptions.RequestException as e_general:
    # Handle ambiguous exceptions while handling request
    error_message = '{0}:  {1}'.format('RequestException', e_general)

else:
    print(response.json())

finally:
    if error_message:
        print(error_message)



###############################################################################
# Backup existing geolocation database
###############################################################################
url = '{0}{1}'.format(bigip, library['bash'])
session.headers.update({'Content-Type': 'application/json'})

###############################################################################
#       Create backup directory
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'mkdir /shared/GeoIP_backup\'"}'
sendRequest(url, session, data)

###############################################################################
#       Copy existing geoip db to back location
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'cp -R /shared/GeoIP/* /shared/GeoIP_backup/\'"}'
sendRequest(url, session, data)

###############################################################################
# Installing the geolocation database update
###############################################################################

###############################################################################
#       Fix md5 file
#       If you run md5sum in a different directory, then the md5 file needs to
#       specify the directory or it will be unable to find it.  This adds the
#       full path in front.
#       Note:  md5sum is insanely specific:  
#       <md5sum_checksum><space><space><file_name>
#
#       todo:   BU existing file before modifying with savebu=True
###############################################################################
def fixMD5file(filename, savebu=False):
    with open(filename, 'r+') as fo:
        old = fo.read().split()
        fo.seek(0)
        fpfn = "{0}  /tmp/{1}".format(old[0],old[1])
        fo.write(fpfn)
        fo.truncate()
        return fpfn

md5file = fixMD5file('ip-geolocation-v2-2.0.0-20220228.573.0.zip.md5')
###############################################################################
#       Upload geolocation database md5 and db zip
###############################################################################
try:
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(bigip_ip, username='root', password='default')

    with SCPClient(ssh.get_transport() ) as scp:
        scp.put('ip-geolocation-v2-2.0.0-20220228.573.0.zip.md5', '/tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip.md5')
   
    with SCPClient(ssh.get_transport() ) as scp:
        scp.put('ip-geolocation-v2-2.0.0-20220228.573.0.zip', '/tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip')

except AuthenticationException:
    print("Authentication files, please verify the credentials")
except SSHException as e:
    print("Unable to establish SSH connection: {0}".format(e) )
except BadHostKeyException as e:
    print("Unable to verify server's host key: {0}".format(e) )
except SCPException as e:
    print("Error while trying to scp files to server: {0}".format(e) )
finally:
    ssh.close()


###############################################################################
#       md5sum -c <ip-geolocationfile>.zip.md5, Verify that md5sum returns OK
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'md5sum -c /tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip.md5\'"}'
r = sendRequest(url, session, data)['commandResult'].split()

if r[1] != 'OK':
    print("MD5 Failed check.  Uploaded zip integrity is questionable, exiting")
    exit(-1)

###############################################################################
#       unzip <ip-geolocationfile>.zip
#       Confusingly, this will unload the files into: /var/service/restjavad
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'unzip /tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip\'"}'
r = sendRequest(url, session, data)['commandResult']

# Process the return and extract all the rpm filenames from the unzip process.
# discard the Archive message, README, and so on by only looking for .rpm files
rpmlist = []
for line in r.splitlines():
    name = line.split()[1]

    if name.endswith('.rpm'):
        rpmlist.append(name)

###############################################################################
#       for each RPM file:     geoip_update_data -f </path/to/rpm>
###############################################################################
# For each rpm file, build a data body which involves working around some b string limitations
# and inserting the rpm file name.  Then run geoip_update_data to update the database.
# Note the weird/obscure location that unzipping the archive ends up in
obscurePath='/var/service/restjavad'
for rpm in rpmlist:
    insert = "-c \'geoip_update_data -f {0}/{1}\'".format(obscurePath, rpm)
    insert = insert.encode('UTF8')
    data = b'{"command": "run", "utilCmdArgs": "' + insert + b'"}'
    
    r = sendRequest(url, session, data)
    print(r)

###############################################################################
# Verifying the geolocation database update
#   Note: 12.1.0 > geoip files are in /shared/GeoIP/v2/
#         < 12.1.0 geoip files are in /shared/GeoIP/
#   if upgrade from < 12.1.0 to > 12.1.0, on first update - files will be in /shared/GeoIP/v2/
# geodb files are hardcoded and well known.  Also, will use the symlinks to 
# ensure they are properly pointing at db files.  
###############################################################################
geodb = [   "/shared/GeoIP/v2/F5GeoIP.dat",
            "/shared/GeoIP/v2/F5GeoIPISP.dat",
            "/shared/GeoIP/v2/F5GeoIPOrg.dat",
            "/shared/GeoIP/v2/F5GeoIPv6.dat",
        ]
testip = "104.219.101.154"

for db in geodb:
    insert = "-c \'geoip_lookup -f {0} {1}\'".format(db, testip)
    insert = insert.encode('UTF8')
    data = b'{"command": "run", "utilCmdArgs": "' + insert + b'"}'

    r = sendRequest(url, session, data)
    print(r)

###############################################################################
# clean up the temp files
# Note - this will leave the README.txt file, but its small and inconsequential 
###############################################################################

###############################################################################
#   clean up .rpm files
###############################################################################
for rpm in rpmlist:
    insert = "-c \'rm -f {0}/{1}\'".format(obscurePath, rpm)
    insert = insert.encode('UTF8')
    data = b'{"command": "run", "utilCmdArgs": "' + insert + b'"}'
    
    r = sendRequest(url, session, data)
    print(r)

###############################################################################
#   clean up zip and md5 files
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'rm -f /tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip\'"}'
r = sendRequest(url, session, data)

data = b'{"command": "run", "utilCmdArgs": "-c \'rm -f /tmp/ip-geolocation-v2-2.0.0-20220228.573.0.zip.md5\'"}'
r = sendRequest(url, session, data)

###############################################################################
#   Optional:  clean up Geoip_backup directory
###############################################################################
data = b'{"command": "run", "utilCmdArgs": "-c \'rm -rf /shared/GeoIP_backup\'"}'
r = sendRequest(url, session, data)

print("")