#!/usr/bin/python
"""
###############################################################################
# geolocation-update.py
# Script that handles upgrading Geolocation db updates on F5 equipment.
# Reference:
#   https://support.f5.com/csp/article/K11176
#   https://code.visualstudio.com/docs/python/python-tutorial
#   https://github.com/mhermsdorferf5/bigip-geodb-update
#
# Located here: https://github.com/caliraftdude/Geolocation-automation
#
# Requires python 3.8 and >.  Otherwise omit the walrus operator ( := )
###############################################################################
"""
# Disable annoying line too long (we all have widescreens now...)
# pylint: disable=C0301
from enum import Enum
from datetime import datetime
import os
import sys
import json
import shutil
import requests

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

# Dictionary to translate a status code to an error message
status_code_to_msg = {400:"400 Bad request.  The url is wrong or malformed\n",
                      401:"401 Unauthorized.  The client is not authorized for this action or auth token is expired\n",
                      404:"404 Not Found.  The server was unable to find the requested resource\n",
                      415:"415 Unsupported media type.  The request data format is not supported by the server\n",
                      422:"422 Unprocessable Entity.  The request data was properly formatted but contained invalid or missing data\n",
                      500:"500 Internal Server Error.  The server threw an error while processing the request\n",
}

# Define some exception classes to handle failure cases and consolidate some of the errors
class ValidationError(Exception):
    """
    ValidationError for some of the necessary items in send_request
    """

class InvalidURL(Exception):
    """
    For raising exception if invalid on null urls are passed to send_request
    """
    def __init__(self, message, errors):
        super().__init__(message)
        self.errors = errors

class Method(Enum):
    """
    Class Method(Enum) provides simple enumeration for controlling way
    send_request communicates to target
    """
    GET = 1
    POST = 2
    PATCH = 3
    DELETE = 4


def send_request(url, method=Method.GET, session=None, data=None):
    """
    send_request is used to send a REST call to the device.  By default it assumes
    that this is a GET request (through the default enumeration).  The passed
    session and data are also by default set to None.  In the case of data, this
    is ignored as its only relevant for a POST or PATCH call.  However the session
    is checked against the default and raises if its None.  PATCH and DELETE are
    also not implemented yet and raise.

    Parameters
    ----------
    url : str                                 The url endpoint to send the request to
    method : Method, defaults to Method.GET   One of the valid Method enumerations
    session : obj, defaults to None           Active / valid session object
    data : str, defaults to None              JSON formatted string passed as body in request

    Returns
    -------
    response str on success
    None on failure

    Raises
    ------
    notImplemented      For improper methods
    ValidationError     If the session object is None or inactive
                        The url parameter is missing
    """

    if not url:
        raise InvalidURL("The url is invalid", url)

    error_message = None
    response = None

    try:
        if None is session:
            raise ValidationError("Invalid session provided")

        # Send request and then raise exceptions for 4xx and 5xx issues
        if method is Method.GET:
            response = session.get(url)
        elif method is Method.POST:
            response = session.post(url, data)
        elif method is Method.PATCH:
            raise NotImplementedError("The PATCH method is not implemented yet")
        elif method is Method.DELETE:
            raise NotImplementedError("The DELETE method is not implemented yet")
        else:
            raise NotImplementedError(f"The HTTP method {method} is not supported")

        response.raise_for_status()

    except requests.exceptions.HTTPError:
        # Handle 4xx and 5xx errors here.  Common 4xx and 5xx REST errors here
        if not (error_message := status_code_to_msg.get(response.status_code) ):
            error_message = f"{response.status_code}.  Uncommon REST/HTTP error"

    except requests.exceptions.TooManyRedirects as e_redir:
        # Handle excessive 3xx errors here
        error_message = f"{'TooManyRedirects'}:  {e_redir}"

    except requests.exceptions.ConnectionError as e_conn:
        # Handle connection errors here
        error_message = f"{'ConnectionError'}:  {e_conn}"

    except requests.exceptions.Timeout as e_tout:
        # Handle timeout errors here
        error_message = f"{'Timeout'}:  {e_tout}"

    except requests.exceptions.RequestException as e_general:
        # Handle ambiguous exceptions while handling request
        error_message = f"{'RequestException'}:  {e_general}"

    else:
        return response

    finally:
        # if error message isn't None, there is an error to process and we should return None
        if error_message:
            print(f"send_request() Error:\n{error_message}")
            print(f"url:\t{url}\nmethod:\t{method.value}\ndata:\t{data}")

            if response is not None:
                print(f"response: {response.json()}")

    return None

def fix_md5_file(filename, append_path, savebu=False):
    """
    Fixes the md5 file so that it will check the zip at the correct path
    If you run md5sum in a different directory, then the md5 file needs to
    specify the directory or it will be unable to find it.  This adds the
    full path in front.
    Note:  md5sum is insanely specific:
        <md5sum_checksum><space><space><file_name>

    Parameters
    ----------
    filename : str
        Valid filename with resolvable path from cwd
    append_path : str
        path to append in the file
    savebu : boolean, default False
        If you a bu of the file should be made prior to modification

    Returns
    -------
        Fixed str saved within the md5 file
    """
    with open(filename, 'r+', encoding='UTF-8') as fileobj:
        if savebu:
            bufilename = (f"{filename}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.backup" )
            shutil.copy(filename, bufilename)

        old = fileobj.read().split()
        fileobj.seek(0)
        fpfn = f"{old[0]}  {append_path}/{old[1]}"
        fileobj.write(fpfn)
        fileobj.truncate()
        return fpfn

def get_auth_token(uri=None, username='admin', password='admin'):
    """
    takes credentials and attempts to obtain an access token from the target
    system.

    Parameters
    ----------
    uri : str       Base URL to call api
    username : str, defaults to 'admin', username for account on target system
    password : str, defaults to 'admin', password for account on target system

    Returns
    -------
    token : str     on success
    None            on failure
    """
    assert uri is not None

    url = f"{uri}{library['auth-token']}"
    data = {'username':username, 'password':password, 'loginProviderName':'tmos'}

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.verify = False

        # Get authentication token
        if (response:= send_request(url, method=Method.POST, session=session, data=json.dumps(data)) ) is None:
            print("Error attempting to get access token.")
            return None

        # Save token and double check its good
        token = response.json()['token']['token']
        url = f"{uri}{library['mng-tokens']}/{token}"
        session.headers.update({'X-F5-Auth-Token' : token})

        if (response := send_request(url, Method.GET, session) ) is None:
            print(f"Error attempting to validate access token {token}.")
            return None

        return token


def backup_geo_db(uri, token=None):
    """
    Creates a backup directory on target device and then backs the existing
    geolocation db up to that location.

    Parameters
    ----------
    uri : str       Base URL to call api
    token : str     Valid access token for this API endpoint

    Returns
    -------
    True    on success
    False   on failure
    """
    assert uri is not None
    assert token is not None

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Create the backup directory
        url = f"{uri}{library['bash']}"
        data = b'{"command": "run", "utilCmdArgs": "-c \'mkdir /shared/GeoIP_backup\'"}'

        # If the backup directory was created, copy the existing db into the backup directory
        if (send_request(url, Method.POST, session, data)) is not None:
            data = b'{"command": "run", "utilCmdArgs": "-c \'cp -R /shared/GeoIP/* /shared/GeoIP_backup/\'"}'

            if (send_request(url, Method.POST, session, data) ) is None:
                print("Unable to backup existing geolocation database")
                return False

        else:
            print("Unable to create backup directory, geolocation db will not be backed up")
            return False

    return True

def get_geoip_version(uri, token=None):
    """
    Makes a call to run 'geoip_lookup 104.219.101.154' on the F5 to extract
    the db date/version

    Parameters
    ----------
    uri : str       Base URL to call api
    token : str     Valid access token for this API endpoint

    Returns
    -------
    str     date/version string on success
    None    on failure
    """
    assert uri is not None
    assert token is not None

    with requests.Session() as session:
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False
        retval = None

        url = f"{uri}{library['bash']}"
        data = b'{"command": "run", "utilCmdArgs": "-c \'geoip_lookup 104.219.101.154\'"}'

        if( response:=send_request(url, Method.POST, session, data)) is not None:

            # Convert the response to json, find the commandResult string and splitlines it into a list
            for line in response.json()['commandResult'].splitlines():
                # Walk the list until we find the Copyright and then return the last 8 characters
                if "Copyright" in line:
                    retval = line[-8:]

        return retval

def upload_geolocation_update(uri, token, zip_file, md5_file):
    """
    Uploads an md5 and zip file for geolocation db update of a BIG-IP

    Parameters
    ----------
    uri : str       Base URL to call api
    token : str     Valid access token for this API endpoint
    zip_file : str  full path to a geolocation zip file
    md5_file : str  full path to a respective md5 file for the zip_file

    Returns
    -------
    True on success
    False on failure
    """
    assert uri is not None
    assert token is not None
    assert zip_file is not None
    assert os.path.splitext(zip_file)[-1] == '.zip'
    assert md5_file is not None
    assert os.path.splitext(md5_file)[-1] == '.md5'

    with requests.Session() as session:
        session.headers.update({'Content-Type':'application/octet-stream'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Upload md5 file, its small so a simple upload is all thats necessary
        fix_md5_file(md5_file, '/var/config/rest/downloads', savebu=True)
        url = f"{uri}{library['file-xfr']}{md5_file}"
        size = os.stat(md5_file).st_size
        content_range = f"0-{size-1}/{size}"
        session.headers.update({'Content-Range':content_range})

        with open(md5_file, 'rb') as fileobj:
            if(response:=send_request(url, Method.POST, session, data=fileobj)) is None:
                # Fail hard on md5 upload failure?
                return False

        # upload zip file, this time it must be chunked
        url = f"{uri}{library['file-xfr']}{zip_file}"
        size = os.stat(zip_file).st_size
        chunk_size = 512 * 1024
        start = 0

        with open(zip_file, 'rb') as fileobj:
            # Read a 'slice' of the file, chunk_size in bytes
            while( fslice := fileobj.read(chunk_size) ):

                # Compute the size, start, end and modify the content-range header
                slice_size = len(fslice)
                if slice_size < chunk_size:
                    end = size
                else:
                    end = start+slice_size

                session.headers.update({'Content-Range':f"{start}-{end-1}/{size}"} )

                # Send the slice, if we get a failure, dump out and return false
                if(response:=send_request(url, Method.POST, session, data=fslice)) is None:
                    return False

                start += slice_size

    # Verify the upload was successful by checking the md5sum.
    with requests.Session() as session:
        url = f"{uri}{library['bash']}"
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Verify that the file upload is sane and passes an md5 check
        data = {'command':'run'}
        data['utilCmdArgs'] = f"-c 'md5sum -c {'/var/config/rest/downloads'}/{md5_file}'"

        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is not None:
            retval = response.json()['commandResult'].split()
            if retval[1] != 'OK':
                print("MD5 Failed check.  Uploaded zip integrity is questionable")
                return False

        return True


def install_geolocation_update(uri, token, zip_file):
    """
    Makes a temp directory, copies zip, unzips archive and installs each of the
    geolocation RPMs

    Parameters
    ----------
    uri : str       Base URL to call api
    token : str     Valid access token for this API endpoint
    zip_file: str   Name of zip file to install

    Returns
    -------
    True on success
    False on failure
    """
    assert uri is not None
    assert token is not None

    tmp_folder = '/shared/tmp/geoupdate'
    rpmlist = []

    with requests.Session() as session:
        url = f"{uri}{library['bash']}"
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'X-F5-Auth-Token' : token})
        session.verify = False

        # Create a new directory in /shared/tmp/geoupdate
        data = {'command':'run'}
        data['utilCmdArgs'] = f"-c 'mkdir {tmp_folder}'"
        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
            print("Unable to create tmp folder for installation")
            return False

        # unzip the archive into the /shared/tmp/geoupdate directory
        data['utilCmdArgs'] = f"-c 'unzip -u /var/config/rest/downloads/{zip_file} -d {tmp_folder} -x README.txt'"
        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to unzip archive")
            return False

        # Process the response and extract the names of the rpms
        for line in response.json()['commandResult'].splitlines():
            name = line.split()[1]

            if name.endswith('.rpm'):
                rpmlist.append(name)

        # For each rpm, run the update/installer
        for rpm in rpmlist:
            data['utilCmdArgs'] = f"-c 'geoip_update_data -f {rpm}'"
            if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
                print("Error while trying to install rpm update {rpm}")
                return False

        # cleanup tmp folder
        data['utilCmdArgs'] = f"-c 'rm -rf {tmp_folder}'"
        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete temp folder {tmp_folder}")

        # cleanup uploads
        data['utilCmdArgs'] = f"-c 'rm -f /var/config/rest/downloads/{zip_file}*'"
        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete uploads in /var/config/rest/downloads")

        # cleanup backup folder
        data['utilCmdArgs'] = "-c 'rm -rf /shared/GeoIP_backup'"
        if (response:=send_request(url, Method.POST, session, json.dumps(data))) is None:
            print("Error while trying to delete geolocation backup, /shared/GeoIP_backup")

    return True

def compare_versions(start, end):
    """
    Helper function to compare two geolocation db version and output message

    Parameters
    ----------
    start : str    Beginning version string of geolocation db
    end : str      Ending version string of geolocation db

    Returns
    -------
    0 on success
    1 on failure
    """

    print(f"Starting GeoIP Version: {start}\nEnding GeoIP Version: {end}")

    if int(start) < int(end):
        print("GeoIP DB updated!")
        return 0

    print("ERROR GeoIP DB NOT updated!")
    return 1


def validate_file(path, file):
    """
    Verifies that the file exists and if in the same directory, keeps the basename.
    If its in a relative or different directory, returns the full path resolving
    links and so on.

    Parameters
    ----------
    path : str
        Argument 0 from sys.argv.. the passed current working directory and exe name
    file : str
        Name of the file to check

    Returns
    -------
    Corrected file with full path

    Raises
    ------
    FileNotFoundError if file doesn't exist
    """
    assert path is not None
    assert file is not None

    # unlikely to raise, but there could be an errno.xx for oddly linked CWDs
    cwd = os.path.dirname(os.path.realpath(path))

    # Verify the zip exists, if its in the same directory, clean up the path
    if not os.path.exists(file):
        raise FileNotFoundError(f"Unable to find file {file}")

    # If cwd and file is in same location, just use the basename for the file
    if cwd == os.path.dirname(os.path.realpath(file)):
        retval = os.path.basename(file)
    # otherwise use the full path (and resolve links) to the file
    else:
        retval = os.path.realpath(file)

    return retval


def print_usage():
    """
    Prints out the correct way to call the script
    """
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
    # Disable/suppress warnings about unverified SSL:
    import urllib3
    requests.packages.urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import time

    try:
        if len(sys.argv) < 5:
            raise ValueError

        # Extract cmd line arguments and massage them accordingly
        g_path = sys.argv[0]
        g_bigip = f"https://{sys.argv[1]}"
        g_creds = sys.argv[2]
        g_zip_file = validate_file(g_path, sys.argv[3])
        g_md5_file = validate_file(g_path, sys.argv[4])

        # Handle username/password from creds or environment variable
        if ('BIGIP_PASS' in os.environ ) and (os.environ['BIGIP_PASS'] is not None) and (not ":" in g_creds):
            g_username = g_creds
            g_password = os.environ['BIGIP_PASS']
        else:
            creds = g_creds.split(':',1)
            g_username = creds[0]
            g_password = creds[1]

    except ValueError:
        print("Wrong number of arguments.")
        print_usage()
        sys.exit(-1)

    except FileNotFoundError as e:
        print(f"{e}.  Exiting..")
        print_usage()
        sys.exit(-1)

    # Get the access token
    print("Getting access token")
    if( g_token := get_auth_token(g_bigip, g_username, g_password) ) is None:
        print("Problem getting access token, exiting")
        sys.exit(-1)

    # Because of bug-id: 1108181, subsequent attempts to use a newly acquired, or refreshed, token can fail.
    # A cheap workaround, possibly, is to wait a few seconds
    time.sleep(5)

    # Attempt to backup existing db
    print("Backing up existing db")
    backup_geo_db(g_bigip, g_token)

    # Get starting date/version of geolocation db for comparison
    startVersion = get_geoip_version(g_bigip, g_token)

    # Upload geolocation update zip file
    print("Uploading geolocation updates")
    if False is upload_geolocation_update(g_bigip, g_token, g_zip_file, g_md5_file):
        print("Unable to upload zip and/or md5 file.  Exiting.")
        sys.exit(-1)

    # Install geolocation update
    print("Installing geolocation updates")
    if False is install_geolocation_update(g_bigip, g_token, g_zip_file):
        print("Unable to install the geolocation updates.  Exiting.")
        sys.exit(-1)

    # Get end date/version of geolocation db for comparison
    endVersion = get_geoip_version(g_bigip, g_token)
    sys.exit( compare_versions(startVersion, endVersion) )
