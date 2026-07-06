import hashlib
import requests
import logging
import json
import time
import threading

# Timeout for the actual HTTP auth request. This is the fix for the case
# where a hung network call would leave _auth_in_progress stuck True
# forever, permanently locking out every future auth()/get()/post()/put()
# call until the process was restarted.
REST_AUTH_HTTP_TIMEOUT = 2.0
 
# Timeout for the default requests.Session calls used by get/post/put.
REST_REQUEST_TIMEOUT = 4.0
 
# How long a thread will wait for another thread's in-progress auth to
# finish before giving up and reporting failure.
REST_AUTH_WAIT_TIMEOUT = 2.0

class DVMRest:

    def __init__(self, _host: str, _port: int, _password: str):
        """
        Create a new DVMRest API connection

        Args:
            _host (string): REST endpoint hostname/IP
            _port (int): REST endpoint port
            _password (string): REST authentication password
        """
        # Store connection details
        self.host = _host
        self.port = _port
        # Hash our password
        self.hashPass = hashlib.sha256(_password.encode()).hexdigest()
        # Create requests session
        self.session = requests.Session()
        # Authentication mutex
        self._auth_cv = threading.Condition()
        self._auth_in_progress = False
        # The authenticated token and status
        self.token = None
        self.authenticated = False
        # Logger
        self.logger = logging.getLogger(__name__)

    def auth(self) -> bool:
        """
        Authenticate with the DVM REST API

        Inlucdes threading mutex to ensure that only one auth process can happen at a time
        Should greatly reduce the annoying 401/REST AUTH errors

        Returns:
            bool: True on successful authentication, otherwise False
        """

        # Get the auth mutex
        with self._auth_cv:
            # If we're already authenticated, return True
            if self.authenticated:
                return True
            # If there's an auth already in progress, wait for it to complete
            if self._auth_in_progress:
                self.logger.warning("REST auth already in progress, waiting for completion")
                # wait_for() atomically releases the lock while waiting and re-acquires it on wakeup
                self._auth_cv.wait_for(
                    lambda: not self._auth_in_progress,
                    timeout = REST_AUTH_WAIT_TIMEOUT
                )
                # If auth is still in progress, we timed out
                if self._auth_in_progress:
                    self.logger.error("Timed out waiting for in-progress REST authentication to compelte")
                # Return if we're authed
                return self.authenticated
            # If the above two didn't fire, noone else is authenticating and we should grab it and start
            self._auth_in_progress = True
        
        # Flag for whether we successfully auth'd
        success = False
        # Try to auth
        try:
            # Request an auth token
            result = self.session.put(
                url="http://%s:%u/auth" % (self.host, self.port),
                headers={'Content-type': 'application/json'},
                json={'auth': self.hashPass},
                timeout=REST_AUTH_HTTP_TIMEOUT,
            )
 
            # Debug request/result prints
            self.logger.debug("--- REQ ---")
            self.logger.debug(result.request.url)
            self.logger.debug(result.request.headers)
            self.logger.debug(result.request.body)
            self.logger.debug("--- RESP ---")
            self.logger.debug(result.url)
            self.logger.debug(result.headers)
            self.logger.debug(result.content)
 
            # Parse the JSON response
            response = json.loads(result.content)
 
            # If we're missing the status JSON block, error
            if "status" not in response:
                self.logger.error(
                    "Invalid response received from REST API at %s:%u during auth exchange: %s"
                    % (self.host, self.port, result.content)
                )
            # If we got any other status than 200 OK, error
            elif response["status"] != 200:
                self.logger.error(
                    "Got error from REST API at %s:%u during auth exchange: %s"
                    % (self.host, self.port, response.get("message"))
                )
            # This normally shouldn't happen but we catch a valid response with no token as an error
            elif "token" not in response:
                self.logger.error(
                    "Auth response from %s:%u did not include a token: %s"
                    % (self.host, self.port, response)
                )
            # If all the checks pass, we got an auth token, yay
            else:
                self.token = response["token"]
                success = True
                self.logger.info(
                    "Successfully authenticated with REST API at %s:%u" % (self.host, self.port)
                )
        
        # Catch any errors as a failure
        except Exception as ex:
            self.logger.error(
                "Caught exception during REST API authentication to %s:%u: %s"
                % (self.host, self.port, ex)
            )
            success = False

        # Every path above funnels through here, so _auth_in_progress is
        # guaranteed to be cleared exactly once no matter what happened.
        with self._auth_cv:
            self.authenticated = success
            self._auth_in_progress = False
            self._auth_cv.notify_all()

        # Finally, return the auth result
        return success
    
    def _ensure_auth(self) -> None:
        """
        This function makes sure that we've authenticated with the endpoint before making
        a GET/PUSH/POST call
        """
        if not self.authenticated:
            if not self.auth():
                raise PermissionError(
                    "Cannot handle REST endpoint at %s:%u, authentication failed" % (self.host, self.port)
                )
            
    def _request(self, method: str, path: str, data: dict = None) -> dict:
        """
        Generic handler for any of GET/PUSH/POST requests so we only have to
        write all the mutex and auth logic once

        Args:
            method (str): GET/PUT/POST
            path (str): endpoint on the REST server
            data (dict, optional): data to write to the endpoint. Defaults to None.

        Returns:
            dict: data returned from REST endpoint
        """

        # Validate method
        if method not in ('GET','POST','PUT'):
            self.logger.error("Invalid request method %s" % method)
            raise ValueError("Invalid request method %s" % method)
        
        # Debug prints
        self.logger.debug("Got REST %s for %s" % (method, path))
        if data is not None:
            self.logger.debug(data)

        # Ensure we're authenticated
        self._ensure_auth()

        # Capture the current token so it doesn't change on us mid-request
        with self._auth_cv:
            token = self.token

        # Prepare request data
        kwargs = {
            'method': method,
            'url': "http://%s:%u/%s" % (self.host, self.port, path),
            'headers': {'X-DVM-Auth-Token': token},
            'allow_redirects': False,
            'timeout': REST_REQUEST_TIMEOUT,
        }

        # Add data if PUT/POST
        if method in ('POST', 'PUT'):
            kwargs['headers']['Content-type'] = 'application/json'
            kwargs['json'] = data

        # Make the request
        result = self.session.request(**kwargs)

        # Debug print of request and response
        self.logger.debug("--- REQ ---")
        self.logger.debug("    %s" % result.request.url)
        self.logger.debug("    %s" % result.request.headers)
        self.logger.debug("    %s" % result.request.body)
        self.logger.debug("--- RESP ---")
        self.logger.debug("    %s" % result.url)
        self.logger.debug("    %s" % result.headers)
        self.logger.debug("    %s" % result.content)

        # GET responses have historically contained stray escaped newlines that break json.loads
        content = result.content.decode('utf-8').replace("\\n", "")
        resultObj = json.loads(content)

        # Ensure we got a response status
        if "status" not in resultObj:
            self.logger.error("Got invalid response for REST path %s: %s" % (path, content))
            raise ValueError("Got invalid response for REST path %s: %s" % (path, content))
 
        # If we got a 401, we need to re-auth
        elif resultObj["status"] == 401:
            self.logger.warning("Got 401 unauthorized, re-authenticating with REST endpoint")
            with self._auth_cv:
                self.authenticated = False
            # If auth failed, error out
            if not self.auth():
                self.logger.error("Failed to re-authenticate")
                raise PermissionError("Failed to re-authenticate with REST endpoint!")
            # Retry the request with the new token
            return self._request(method, path, data)
 
        # If we got a non 200 OK, error out
        elif resultObj["status"] != 200:
            self.logger.error(
                "Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj.get("message"))
            )
            raise requests.HTTPError(
                "Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj.get("message"))
            )
 
        else:
            return resultObj
       
    def get(self, path: str) -> dict:
        """
        Perform a REST GET to the specified path and return the result

        Args:
            path (str): REST path to query

        Returns:
            dict: dictionary of returned data
        """

        return self._request('GET', path)
        
    
    def post(self, path: str, data: dict) -> dict:
        """
        POST data to the rest endpoint

        Args:
            path (str): REST endpoint path
            data (dict): dictionary of data to post

        Returns:
            dict: response dictionary
        """

        return self._request('POST', path, data)
        

    def put(self, path: str, data: dict) -> dict:
        """
        PUT data to the specified REST endpoint

        Args:
            path (str): REST endpoint path
            data (dict): dictionary of data to PUT

        Returns:
            dict: response dictionary
        """

        return self._request('PUT', path, data)