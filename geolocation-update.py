#!/usr/bin/python
###############################################################################
# geolocation-update.py
# Script that handles upgrading Geolocation db updates on F5 equipment.
# Referece:
#   https://support.f5.com/csp/article/K11176
#   https://code.visualstudio.com/docs/python/python-tutorial
#   https://github.com/mhermsdorferf5/bigip-geodb-update
#
# Located here: https://github.com/caliraftdude/Geolocation-automation
# 
# Requires python 3.8 and >.  Otherwise omit the walrus operator ( := )
###############################################################################
import os
import sys
import json
import requests
from enum import Enum
from datetime import datetime
import shutil

# Library of REST API end points for frequently used automation calls
library = {'auth-token':'/mgmt/shared/authn/login',
           'mng-tokens':'/mgmt/shared/authz/tokens',
           'pass-policy':'/mgmt/tm/auth/password-policy',
           'pass-change':'/mgmt/tm/auth/user/',
           'get-version':'/mgmt/tm/sys/version',
           'file-xfr':'/mgmt/shared/file-transfer/uploads/',    # uploads to /var/config/rest/downloads/
           'iso-xfr':'/cm/autodeploy/software-image-uploads/',  # uploads to /shared/images/
           'mgmt-tasks':'/mgmt/shared/iapp/package-management-tasks',
           'do-info':'/mgmt/shared/declarative-onboarding/info',
           'as3-info':'/mgmt/shared/appsvcs/info',
           'do-upload':'/mgmt/shared/declarative-onboarding/',
           'do-tasks':'/mgmt/shared/declarative-onboarding/task/',
           'as3-upload':'/mgmt/shared/appsvcs/declare?async=true',
           'as3-tasks':'/mgmt/shared/appsvcs/task/',
           'bash':'/mgmt/tm/util/bash',
}

# Define some exception classes to handle failure cases and consolidate some of the errors
class ValidationError(Exception):
    def __init__(self, message):
        super().__init__(message)

class InvalidURL(Exception):
    def __init__(self, message, errors):
        super().__init__(message)
        self.errors = errors

class notImplemented(Exception):
    def __init__(self, message):
        super().__init__(message)

# Simple enumeration to clean up sendRequest method choices
class Method(Enum):
    GET = 1
    POST = 2
    PATCH = 3
    DELETE = 4

###############################################################################
# sendRequest()
#   url         The url endpoint to send the request to
#   method      One of the valid Method enumerations
#   session     Active session object
#   data        Data that is put into the body, normally for POST requests
#
#   Raises:
#       InvalidURL          The url parameter is missing
#       notImplemented      For improper methods
#       ValidationError     If the session object is None or inactive
###############################################################################
def sendRequest(url, method=Method.GET, session=None, data=None):
    
    if not url:
        raise InvalidURL("The url is invalid", url)

    try:
        error_message = None
        response = None

        if None == session:
            raise ValidationError("Invalid session provided")

        # Send request and then raise exceptions for 4xx and 5xx issues
        if method is Method.GET:
            response = session.get(url)
        elif method is Method.POST:
            response = session.post(url, data)
        elif method is Method.PATCH:
            raise notImplemented("The PATCH method is not implemented yet")
        elif method is Method.DELETE:
            raise notImplemented("The DELETE method is not implemented yet")
        else:
            raise notImplemented("The HTTP method {0} is not supported".format(method))

        response.raise_for_status()

    except requests.exceptions.HTTPError as e_http:
        # Handle 4xx and 5xx errors here.  Common 4xx and 5xx REST errors here
        if response.status_code == 400:
            error_message = "400 Bad request.  The url is wrong or malformed\n"
        elif response.status_code == 401:
            error_message = "401 Unauthorized.  The client is not authorized for this action or auth token is expired\n"
        elif response.status_code == 404:
            error_message = "404 Not Found.  The server was unable to find the requested resource\n"
        elif response.status_code == 415:
            error_message = "415 Unsupported media type.  The request data format is not supported by the server\n"
        elif response.status_code == 422:
            error_message = "422 Unprocessable Entity.  The request data was properly formatted but contained invalid or missing data\n"
        elif response.status_code == 500:
            error_message = "500 Internal Server Error.  The server threw an error while processing the request\n"
        else:
            error_message = "{0}.  Uncommon REST/HTTP error\n".format(response.status_code)
        
        status_code = response.status_code

    except requests.exceptions.TooManyRedirects as e_redir:
        # Handle excessive 3xx errors here
        error_message = '{0}:  {1}'.format('TooManyRedirects', e_redir)

    except requests.exceptions.ConnectionError as e_conn:
        # Handle connection errors here
        error_message = '{0}:  {1}'.format('ConnectionError', e_conn)

    except requests.exceptions.Timeout as e_tout:
        # Handle timeout errors here
        error_message = '{0}:  {1}'.format('Timeout', e_tout)    

    except requests.exceptions.RequestException as e_general:
        # Handle ambiguous exceptions while handling request
        error_message = '{0}:  {1}'.format('RequestException', e_general)

    else:
        #return response.json()  THIS IS GOING TO BREAK STUFF XXX
        return response

    finally:
        # if error message isn't None, there is an error to process and we should return None
        if error_message:
            print("sendRequest() Error:\n{0}".format(error_message))
            print("url:\t{0}\nmethod:\t{1}\ndata:\t{2}".format(url, method.value, data))
            
            if response is not None:
                print("response: {0}".format(response.json()))
        
            return None

###############################################################################
# fixMD5File()
#   filename        Valid filename with resolvable path from cwd
#   append_path     path to append in the file
#   savebu          If you a bu of the file should be made prior to modification
#
# Notes:
#   If you run md5sum in a different directory, then the md5 file needs to
#   specify the directory or it will be unable to find it.  This adds the
#   full path in front.
#   Note:  md5sum is insanely specific:  
#       <md5sum_checksum><space><space><file_name>
#
###############################################################################
def fixMD5File(filename, append_path, savebu=False):
    with open(filename, 'r+') as fo:
        if savebu:
            bufilename = ("{0}-{1}.backup".format(filename, datetime.now().strftime('%Y%m%d-%H%M%S')) )
            shutil.copy(filename, bufilename)

        old = fo.read().split()
        fo.seek(0)
        fpfn = "{0}  {1}/{2}".format(old[0],append_path,old[1])
        fo.write(fpfn)
        fo.truncate()
        return fpfn

###############################################################################
# getAuthToken()
#   uri             Base URL to call api and get token
#   username        username for account
#   password        password for account
# 
# returns:
#   access token on success
#   None on failure
###############################################################################
def getAuthToken(uri=None, username='admin', password='admin'):
    assert(uri!=None)

    url = "{0}{1}".format(uri, (library['auth-token']))
    data = {'username':username, 'password':password, 'loginProviderName':'tmos'}

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.verify = False

        # Get authentication token
        if (response:= sendRequest(url, method=Method.POST, session=session, data=json.dumps(data)) ) is None:
            print("Error attempting to get access token.")
            return None
        
        # Save token and double check its good
        token = response.json()['token']['token']
        url = "{0}{1}/{2}".format(bigip, (library['mng-tokens']), token )
        session.headers.update({'X-F5-Auth-Token' : token})

        if (response := sendRequest(url, Method.GET, session) ) is None:
            print("Error attempting to validate access token {1}.".format(token))
            return None

        return token

###############################################################################
# backupGeoDB()
#   uri             Base URL to call api and get token
#   accessToken     Valid accessToken
# 
# returns
#   True on success
#   False on failure
###############################################################################
def backupGeoDB(uri, accessToken=None):
    assert(uri!=None)
    assert(accessToken!=None)

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : accessToken})
        session.verify = False

        # Create the backup directory
        url = '{0}{1}'.format(uri, library['bash'])
        data = b'{"command": "run", "utilCmdArgs": "-c \'mkdir /shared/GeoIP_backup\'"}'

        if (response:=sendRequest(url, Method.POST, session, data)) is not None:
            # If the backup directory was created, copy the existing db into the backup directory
            data = b'{"command": "run", "utilCmdArgs": "-c \'cp -R /shared/GeoIP/* /shared/GeoIP_backup/\'"}'

            if (response:=sendRequest(url, Method.POST, session, data) ) is None:
                print("Unable to backup existing geolocation database")
                return False

        else:
            print("Unable to create backup directory, geolocation db will not be backed up")
            return False

    return True

###############################################################################
# getGeoIPVersion()
# Makes a call to run 'geoip_lookup 104.219.101.154' on the F5 to extract the db
# date/version
#
# Arguments
#   uri             Base URL to call api and get token
#   accessToken     Valid accessToken
# returns
#   date/version string on success
#   None on failure
###############################################################################
def getGeoIPVersion(uri, token=None):
    assert(uri!=None)
    assert(token!=None)

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        url = '{0}{1}'.format(uri, library['bash'])
        data = b'{"command": "run", "utilCmdArgs": "-c \'geoip_lookup 104.219.101.154\'"}'

        if( response:=sendRequest(url, Method.POST, session, data)) is not None:
            version = None

            # Convert the response to json, find the commandResult string and splitlines it into a list
            for line in response.json()['commandResult'].splitlines():
                # Walk the list until we find the Copyright and then return the last 8 characters
                if "Copyright" in line:
                    return line[-8:]

        else:
            # something failed, so return None
            return None

###############################################################################
# uploadGeoLocationUpdate()
# Uploads an md5 and zip file for geolocation db update
#
# Arguments
#   uri         Base URL to call api   
#   token       Valid access token for this API endpoint
#   zipFile     full path to a geolocation zip file
#   md5File     full path to a respective md5 for geolocation zip file
#
# returns
#   True on success
#   False on failure
###############################################################################
def uploadGeoLocationUpdate(uri, token, zipFile, md5File):
    assert(uri!=None)
    assert(token!=None)
    assert(zipFile!=None)
    assert(os.path.splitext(zipFile)[-1] == '.zip')
    assert(md5File!=None)
    assert(os.path.splitext(md5File)[-1] == '.md5')

    with requests.Session() as session:
        session.headers.update({'Content-Type':'application/octet-stream'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Upload md5 file, its small so a simple upload is all thats necesary
        fixMD5File(md5File, '/var/config/rest/downloads', savebu=True)
        url = '{0}{1}{2}'.format(bigip, library['file-xfr'], md5File)
        size = os.stat(md5File).st_size
        content_range = "0-{0}/{1}".format( (size-1), size)
        session.headers.update({'Content-Range':content_range})

        with open(md5File, 'rb') as f:
            if(response:=sendRequest(url, Method.POST, session, data=f)) is None:
                # Fail hard on md5 upload failure?
                return False

        # upload zip file, this time it must be chunked
        url = '{0}{1}{2}'.format(bigip, library['file-xfr'], zipFile)
        size = os.stat(zipFile).st_size
        chunk_size = 512 * 1024
        start = 0

        with open(zipFile, 'rb') as f:
            # Read a 'slice' of the file, chunk_size in bytes
            while( fslice := f.read(chunk_size) ):

                # Compute the size, start, end and modify the content-range header
                slice_size = len(fslice)
                if slice_size < chunk_size:
                    end = size
                else:
                    end = start+slice_size
                
                session.headers.update({'Content-Range':"{0}-{1}/{2}".format(start, end-1, size)} )

                # Send the slice, if we get a failure, dump out and return false
                if(response:=sendRequest(url, Method.POST, session, data=fslice)) is None:
                    return False

                start += slice_size

    # Verify the upload was successful by checking the md5sum.       
    with requests.Session() as session:
        url = '{0}{1}'.format(uri, library['bash'])
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Verify that the file upload is sane and passes an md5 check
        data = {'command':'run'}
        data['utilCmdArgs'] = "-c 'md5sum -c {0}/{1}'".format('/var/config/rest/downloads', md5File)

        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is not None:
            retval = response.json()['commandResult'].split()
            if retval[1] != 'OK':
               print("MD5 Failed check.  Uploaded zip integrity is questionable")
               return False

        return True

###############################################################################
# installGeolocationUpdate()
# Makes a temp directory, copies zip, unzips archive and installs each of the
# geolocation RPMs
#
# Arguments
#   uri         Base URL to call api   
#   token       Valid access token for this API endpoint
#
# returns
#   True on success
#   False on failure
###############################################################################
def installGeolocationUpdate(uri, token, zipFile):
    assert(uri!=None)
    assert(token!=None)
    
    tmpFolder = '/shared/tmp/geoupdate'
    rpmlist = []

    with requests.Session() as session:
        url = '{0}{1}'.format(uri, library['bash'])
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Create a new directory in /shared/tmp/geoupdate
        data = {'command':'run'}
        data['utilCmdArgs'] = "-c 'mkdir {0}'".format(tmpFolder)
        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
            print("Unable to create tmp folder for installation")
            return False

        # unzip the archive into the /shared/tmp/geoupdate directory
        data['utilCmdArgs'] = "-c 'unzip -u /var/config/rest/downloads/{0} -d {1} -x README.txt'".format(zipFile, tmpFolder)
        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to unzip archive")
            return False
        
        # Process the response and extract the names of the rpms
        for line in response.json()['commandResult'].splitlines():
            name = line.split()[1]

            if name.endswith('.rpm'):
                rpmlist.append(name)

        # For each rpm, run the update/installer
        for rpm in rpmlist:
            data['utilCmdArgs'] = "-c 'geoip_update_data -f {0}'".format(rpm)
            if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
                print("Error while trying to install rpm update {0}".format(rpm))
                return False
            
        # cleanup tmp folder
        data['utilCmdArgs'] = "-c 'rm -rf {0}'".format(tmpFolder)
        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete temp folder {0}".format(tmpFolder))

        # cleanup uploads
        data['utilCmdArgs'] = "-c 'rm -f /var/config/rest/downloads/{0}*'".format(zipFile)
        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete uploads in /var/config/rest/downloads")

        # cleanup backup folder
        data['utilCmdArgs'] = "-c 'rm -rf /shared/GeoIP_backup'"
        if (response:=sendRequest(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete geolocation backup, /shared/GeoIP_backup")

    return True

###############################################################################
# compareVersions()
# Helper function to compare two geolocation db version and output message
#
# Arguments
#   start     Beginning version string of geolocation db
#   end       Ending version string of geolocation db
#
# returns
#   0 on success
#   1 on failure
###############################################################################
def compareVersions(start, end):
    print("Starting GeoIP Version: {0}\nEnding GeoIP Version: {1}".format(start, end))

    if int(start) < int(end):
        print("GeoIP DB updated!")
        return 0
    else:
        print("ERROR GeoIP DB NOT updated!")
        return 1

###############################################################################
# validateFile()
#
# arguments:
#   path    argument 1 from sys.argv
#   file    file to check
# returns:
#   corrected file with full path
# raises:
#   FileNotFoundError if file doesn't exist
###############################################################################
def validateFile(path, file):
    assert(path!= None)
    assert(file!=None)

    cwd = os.path.dirname(os.path.realpath(path))

    # Verify the zip exists, if its in the same directory, clean up the path
    if( not os.path.exists(file) ):
        raise FileNotFoundError("Unable to find file {0}".format(file))
    else:
        # If cwd and file is in same location, just use the basename for the file
        if (cwd == os.path.dirname(os.path.realpath(file)) ):
            retval = os.path.basename(file)
        # otherwise use the full path (and resolve links) to the file
        else:
            retval = os.path.realpath(file)
        
    return retval

###############################################################################
# printUsage()
#
# simple routine to print the usage information
###############################################################################
def printUsage():
    print("Usage: geolocation-update.py <hostname/ip> <credentials> <zip> <md5>")
    print("\t<hostname/ip> is the resolvable address of the F5 device")
    print("\t<credentials> are the username and password formatted as username:password")
    print("\t<zip> is the name, and path if not in the same directory, to the geolocation zip package")
    print("\t<md5> is the name, and path if not in the same directory, to the geolocation zip md5 file")
    print("\nNOTE:  You can omit the password and instead put it in an env variable named BIGIP_PASS")

###############################################################################
# main() entry point if run from cmdline as script
###############################################################################
if __name__ == "__main__":
    # Disable/supress warnings about unverified SSL:
    import urllib3
    requests.packages.urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        path, hostname, creds, zip, md5 = sys.argv

        # Handle username/password from creds or environment variable
        if ('BIGIP_PASS' in os.environ ) and (os.environ['BIGIP_PASS'] is not None) and (not ":" in creds):
            username = creds
            password = os.environ['BIGIP_PASS']
        else:
            creds = creds.split(':',1)
            username = creds[0]
            password = creds[1]

        # Modify the ip/hostname into a url
        bigip='https://{0}'.format(hostname)

        zipFile = validateFile(path, zip)
        md5File = validateFile(path, md5)

    except ValueError:
        print("Wrong number of arguments.")
        sys.exit(-1)

    except FileNotFoundError as e:
        print("{0}.  Exiting..".format(e))
        sys.exit(-1)


    # Get the access token
    print("Getting access token")
    if( token := getAuthToken(bigip, username, password) ) is None:
        print("Problem getting access token, exiting")
        sys.exit(-1)

    # Attempt to backup existing db
    print("Backing up existing db")
    backupGeoDB(bigip, token)

    # Get starting date/version of geolocation db for comparison
    startVersion = getGeoIPVersion(bigip, token)

    # Upload geolocation update zip file
    print("Uploading geolocation updates")
    if( False == uploadGeoLocationUpdate(bigip, token, zipFile, md5File) ):
        print("Unable to upload zip and/or md5 file.  Exiting.")
        sys.exit(-1)

    # Install geolocation update
    print("Installing geolocation updates")
    if( False == installGeolocationUpdate(bigip, token, zipFile) ):
        print("Unable to install the geolocation updates.  Exiting.")
        sys.exit(-1)

    # Get end date/version of geolocation db for comparison
    endVersion = getGeoIPVersion(bigip, token)
    sys.exit( compareVersions(startVersion, endVersion) )