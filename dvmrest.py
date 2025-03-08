import hashlib
import requests
import logging
import json
import time

class DVMRest:

    def __init__(self, _host, _port, _password):
        # Store connection details
        self.host = _host
        self.port = _port
        # Hash our password
        self.hashPass = hashlib.sha256(_password.encode()).hexdigest()
        # Create requests session
        self.session = requests.Session()
        # Authenticated status
        self.authInProgress = False
        self.token = None
        self.authenticated = False


    def auth(self) -> bool:
        """
        Authenticate with the DVM REST API

        Returns:
            bool: True on successful authentication, otherwise False
        """

        # Wait for auth if in progress
        if self.authInProgress:
            logging.warn("Auth already in progress!")
            timeout = time.time() + 0.5
            while not self.authenticated:
                if time.time() > timeout:
                    break
            return self.authenticated
        else:
            # Capture the auth process
            self.authInProgress = True
            self.authenticated = False
            try:
                # Make a request to get the auth token
                result = self.session.put(
                    url = "http://%s:%u/auth" % (self.host, self.port),
                    headers = {'Content-type': 'application/json'},
                    json = {'auth': self.hashPass}
                )
                # Debug
                logging.debug("--- REQ ---")
                logging.debug(result.request.url)
                logging.debug(result.request.headers)
                logging.debug(result.request.body)
                logging.debug("--- RESP ---")
                logging.debug(result.url)
                logging.debug(result.headers)
                logging.debug(result.content)
                # Try to convert the response to JSON
                response = json.loads(result.content)
                if "status" in response:
                    if response["status"] != 200:
                        logging.error("Got error from REST API at %s:%u during auth exchange: %s" % (self.host, self.port, response["message"]))
                        self.authInProgress = False
                        return False
                    if "token" in response:
                        self.token = response["token"]
                        self.authenticated = True
                        logging.info("Successfully authenticated with REST API at %s:%u" % (self.host, self.port))
                        self.authInProgress = False
                        return True
                else:
                    logging.error("Invalid response received from REST API at %s:%u during auth exchange: %s" % (self.host, self.port, result.content))
                    self.authInProgress = False
                    return False
            except Exception as ex:
                logging.error("Caught exception during REST API authentication to %s:%u: %s" % (self.host, self.port, ex))
                self.authInProgress = False
                return False
        
        
    def get(self, path: str) -> dict:
        """
        Perform a REST GET to the specified path and return the result

        Args:
            path (str): REST path

        Returns:
            dict: dictionary of returned data
        """

        logging.debug("Got REST GET for %s" % path)

        # Auth if we aren't
        if not self.authenticated and not self.authInProgress:
            self.auth()
            
        result = self.session.request(
            method          = 'GET',
            url             = "http://%s:%u/%s" % (self.host, self.port, path),
            headers         = {'X-DVM-Auth-Token': self.token},
            allow_redirects = False
        )

        # Debug
        logging.debug("--- REQ ---")
        logging.debug("    %s" % result.request.url)
        logging.debug("    %s" % result.request.headers)
        logging.debug("    %s" % result.request.body)
        logging.debug("--- RESP ---")
        logging.debug("    %s" % result.url)
        logging.debug("    %s" % result.headers)
        logging.debug("    %s" % result.content)

        # Find any unescaped newlines and remove them
        stripped = result.content.decode('utf-8').replace("\\n", "")
        # Parse JSON
        resultObj = json.loads(stripped)
        if "status" not in resultObj:
            logging.error("Got invalid response for REST path %s: %s" % (path, stripped))
            raise ValueError("Got invalid response for REST path %s: %s" % (path, stripped))
        # If we got a 401, re-auth and try again
        elif resultObj["status"] == 401:
            logging.warning("Got 401 unauthorized, re-authenticating with REST endpoint")
            if not self.auth():
                logging.error("Failed to authenticate")
                raise PermissionError("Failed to authenticate with REST endpoint!")
            else:
                return self.get(path)
        # If we got any other error, return false
        elif resultObj["status"] != 200:
            logging.error("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
            raise requests.HTTPError("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
        # Return result on success
        else:
            return resultObj
        
    
    def post(self, path: str, data: dict) -> dict:
        """
        POST data to the rest endpoint

        Args:
            path (str): REST endpoint path
            data (dict): dictionary of data to post

        Returns:
            dict: response dictionary
        """

        logging.debug("Got REST POST for %s" % path)
        logging.debug(data)

        # Auth if we aren't
        if not self.authenticated and not self.authInProgress:
            self.auth()
            
        result = self.session.request(
            method          = 'POST',
            url             = "http://%s:%u/%s" % (self.host, self.port, path),
            headers         = {'X-DVM-Auth-Token': self.token, 'Content-type': 'application/json'},
            allow_redirects = False,
            json            = data,
        )

        # Debug
        logging.debug("--- REQ ---")
        logging.debug("    %s" % result.request.url)
        logging.debug("    %s" % result.request.headers)
        logging.debug("    %s" % result.request.body)
        logging.debug("--- RESP ---")
        logging.debug("    %s" % result.url)
        logging.debug("    %s" % result.headers)
        logging.debug("    %s" % result.content)

        # Parse JSON
        resultObj = json.loads(result.content)
        if "status" not in resultObj:
            logging.error("Got invalid response for REST path %s: %s" % (path, result.content))
            raise ValueError("Got invalid response for REST path %s: %s" % (path, result.content))
        # If we got a 401, re-auth and try again
        elif resultObj["status"] == 401:
            logging.warning("Got 401 unauthorized, re-authenticating with REST endpoint")
            if not self.auth():
                logging.error("Failed to authenticate")
                raise PermissionError("Failed to authenticate with REST endpoint!")
            else:
                return self.post(path, data)
        # If we got any other error, return false
        elif resultObj["status"] != 200:
            logging.error("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
            raise requests.HTTPError("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
        # Return result on success
        else:
            return resultObj
        

    def put(self, path: str, data: dict) -> dict:
        """
        PUT data to the specified REST endpoint

        Args:
            path (str): REST endpoint path
            data (dict): dictionary of data to PUT

        Returns:
            dict: response dictionary
        """

        logging.debug("Got REST POST for %s" % path)
        logging.debug(data)

        # Auth if we aren't
        if not self.authenticated and not self.authInProgress:
            self.auth()
            
        result = self.session.request(
            method          = 'PUT',
            url             = "http://%s:%u/%s" % (self.host, self.port, path),
            headers         = {'X-DVM-Auth-Token': self.token, 'Content-type': 'application/json'},
            allow_redirects = False,
            json            = data,
        )

        # Debug
        logging.debug("--- REQ ---")
        logging.debug("    %s" % result.request.url)
        logging.debug("    %s" % result.request.headers)
        logging.debug("    %s" % result.request.body)
        logging.debug("--- RESP ---")
        logging.debug("    %s" % result.url)
        logging.debug("    %s" % result.headers)
        logging.debug("    %s" % result.content)

        # Parse JSON
        resultObj = json.loads(result.content)
        if "status" not in resultObj:
            logging.error("Got invalid response for REST path %s: %s" % (path, result.content))
            raise ValueError("Got invalid response for REST path %s: %s" % (path, result.content))
        # If we got a 401, re-auth and try again
        elif resultObj["status"] == 401:
            logging.warning("Got 401 unauthorized, re-authenticating with REST endpoint")
            if not self.auth():
                logging.error("Failed to authenticate")
                raise PermissionError("Failed to authenticate with REST endpoint!")
            else:
                return self.put(path, data)
        # If we got any other error, return false
        elif resultObj["status"] != 200:
            logging.error("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
            raise requests.HTTPError("Got status %d for REST path %s: %s" % (resultObj["status"], path, resultObj["message"]))
        # Return result on success
        else:
            return resultObj