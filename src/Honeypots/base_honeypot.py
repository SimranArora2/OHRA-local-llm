#base_honeypot.py
"""
This is the parent class that implements general things
that every honeypot must be able to perform
"""

import json
import os
import re
import traceback

from abc import abstractmethod
from datetime import datetime

import requests


class BaseHoneypot:
    """
    The parent class for all honeypots

    - Set download_urls (bool) to true to download detected urls

    Functionalities:
    - initialize and check connection to LogHandler and LLMHandler
    - communication with LogHandler (requesting sessionID, logging)
    - communication with LLMHandler (sending data to and handing back responses)

    Not implemented (needs to be implemented by protocol-specific child class):
    - bind_service (binding to a port and establishing a protocol-specific listener)
    - handle_connections (handling of incoming connections)
    """

    def __init__(self, download_urls: bool = False):
        # read environment vars
        self._log_addr = os.environ.get("LOG_HANDLER")
        self.__llm_addr = os.environ.get("LLM_HANDLER")
        credential_path = os.environ.get("CREDENTIALS_FILE")

        if self._log_addr is None or self.__llm_addr is None or credential_path is None:
            raise ValueError("LOG_HANDLER or LLM_HANDLER not specified!")

        # read the credentials and save them
        # support wildcards
        if credential_path == "*":
            self.__credentials = "*"
        else:
            self.__credentials = self.__read_creds(credential_path)

        # check that Log and LLM Handler are ready
        self.__check_available(self._log_addr, "Log Handler")
        self.__check_available(self.__llm_addr, "LLM Handler")

        # dictionary that tracks ip addresses and their matching sessionIDs
        self.__ids = {}

        # flag to set if detected urls should be downloaded or not
        self.__download_urls = download_urls

        # regex for detecting urls
        self.__url_regex = re.compile(
            r"(?:http[s]?:\/\/.)?(?:www\.)?[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)"
        )
        self.__ip_regex = re.compile(
            r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$"
        )

    def __read_creds(self, path: str) -> dict:
        """
        Private helper function to read a json file containing all valid credentials
        that the honeypots should accept
        """
        creds = None
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Provided credentials path was: {path}")

        try:
            with open(path, mode="r", encoding="utf-8") as f:
                creds = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"Provided file path was: {path}")
            raise exc

        return creds

    def __check_available(self, address, name):
        """
        Private helper function to check if the respective module is ready
        This is used to check whether the LogHandler and LLMHandler are initialized
        Note that this function is called when logging is potentially not yet established
        and thus this function raises errors directly, leading to a termination
        """
        # send request to the is_ready api
        try:
            res = requests.get(f"http://{address}/is_ready", timeout=10)
        except requests.exceptions.Timeout as exc:
            print(f"Request to {name} timed out!")
            raise exc
        except requests.exceptions.ConnectionError as exc:
            print(f"Request to {name} not possible!")
            raise exc

        # parse the response - should be json
        try:
            res = res.json()
        except requests.exceptions.JSONDecodeError as exc:
            print(f"Error during the handling of the check to {name}")
            raise exc

        # check if it is ready
        try:
            if not res["ready"]:
                raise RuntimeError(f"{name} is not ready! This is the response:\n{res}")
        except KeyError as exc:
            print(f"Response from {name} did not contain the key 'ready'!")
            raise exc

    def convert_str(self, string) -> str:
        """
        Helper function that checks
        if a string is in bytes and then tries to
        decode it and else just returns the str version
        """
        if isinstance(string, bytes):
            # try to decode and replace invalid chars with placeholders
            return string.decode("utf-8", errors="replace")
        return str(string)

    def get_id(self, ip_addr: str, protocol: str) -> str:
        """
        Helper function that returns the sessionID for an ip address.
        If the ip address has not been seen before a new sessionID is requests.
        As long as this runs the same ip address will get the same sessionID
        """
        if ip_addr in self.__ids:
            return self.__ids[ip_addr]

        # ip address that has not been seen before
        session_id = self.get_session_id(protocol)

        self.__ids[ip_addr] = session_id

        return session_id

    def log(self, content: str, event_type: str = "INFO"):
        """
        Helper function to log application events (i.e. not session logs!)
        This communicates with the /event_log endpoint of the LogHandler (log_wrapper)
        """
        body = {
            "log_type": event_type,
            "timestamp": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
            "content": content,
        }
        res = requests.post(f"http://{self._log_addr}/event_log", json=body, timeout=20)
        if res.status_code != 200:
            # do not abort but print to the system output so it is at least
            # somehow logged
            print("ERROR: Could not log a system event!")
            print(f"This was the event:\n{body}")
            try:
                print(f"This was the response:\n{res.json()}")
            except requests.exceptions.JSONDecodeError:
                # should not occur but better for proper sanitization
                print(f"This was the response:\n{str(res.content)}")

    def session_log(
        self, session_id: str, content: str, event_type: str, protocol: str, ip: str
    ):
        """
        Helper function to log session events (i.e. not application logs!)
        This communicates with the /log endpoint of the log_wrapper
        """
        body = {
            "session_id": session_id,
            "log_type": event_type,
            "timestamp": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
            "protocol": protocol,
            "content": content,
            "ip": ip,
        }
        res = requests.post(f"http://{self._log_addr}/log", json=body, timeout=20)
        if res.status_code != 200:
            print("ERROR: Could not log a session event!")
            print(f"This was the event:\n{body}")
            try:
                print(f"This was the response:\n{res.json()}")
            except requests.exceptions.JSONDecodeError:
                # should not occur but better for proper sanitization
                print(f"This was the response:\n{str(res.content)}")

    def get_session_id(self, protocol: str) -> str:
        """
        Helper function to request a new session id from the Log Handler.

        Input:
        - protocol: str := the protocol to get a sessionID for

        Returns:
        - sessionID: str := the new assigned sessionID

        Raises:
        - RuntimeError := Response code was != 200 so smth went wrong in the
            LogHandler
        - requests.exceptions.Timeout := LogHandler not reachable
        """
        post_data = {"protocol": protocol}
        try:
            res = requests.post(
                f"http://{self._log_addr}/get_id", json=post_data, timeout=10
            )

            if res.status_code != 200:
                self.log(str(res.json()), "FATAL ERROR")
                raise RuntimeError("Could not request session id")

        except requests.exceptions.Timeout as exc:
            self.log(traceback.format_exc(), "FATAL ERROR")
            raise exc

        return res.json()["id"]

    def get_llm_response(
        self,
        user_in: str,
        protocol: str,
        session_id: str,
        username: str = None,
    ) -> str:
        """
        Helper function to get a response from the LLM by communicating
            with the LLMHandler.
        Note: This function does NOT log to the session log! \
        This needs to be handled in the calling code.

        Input:
        - user_in: str := the input from the user
        - protocol: str := the protocol that is running in the honeypot
        - session_id: str := the sessionID of the user
        - username: str := the username of the currently logged in user (Default is None)

        Returns:
        - llm_response: str := the generated response from the LLM

        Raises:
        - RuntimeError: if a LLM response cant be retrieved
        """
        post_data = {
            "protocol": protocol,
            "input": user_in,
            "session_id": session_id,
            "username": username,
        }

        try:
            res = requests.post(
                f"http://{self.__llm_addr}/get_response", json=post_data, timeout=60
            )
            if res.status_code != 200:
                # fatal error as something went wrong in the llm handler/wrapper
                # this most likely will occur if either
                # (a) the LLM api is down or
                # (b) a token budget is used up or
                # (c) a security exception in the LLM api is raised, which would
                # mean that the input contained something harmful or an attempted prompt injection
                self.log(str(res.json()), "FATAL ERROR")
                raise RuntimeError("Could not get LLM response")

        except requests.exceptions.Timeout as exc:
            # fatal error since we did not get a response
            self.log(traceback.format_exc(), "FATAL ERROR")
            raise exc

        if self.__download_urls:
            # check also if there were any urls or ip addresses in the user input
            detected_urls = self.__url_regex.findall(user_in)
            for i in self.__ip_regex.findall(user_in):
                detected_urls.append(i)
            if len(detected_urls) > 0:
                # dispatch the urls to the log handler but do not do anything
                # this should be non-blocking to prevent excessive response waiting times
                # the log handler will return immediately and handle the urls in the background
                # in a thread
                self.log(f"Detected urls/ip addresses: {detected_urls}")
                requests.post(
                    f"http://{self._log_addr}/process_urls",
                    json={"urls": detected_urls},
                    timeout=5,
                )

        # get the actual response
        res = res.json()["response"]
        return res

    def check_username(self, username) -> bool:
        """
        Function to check if a username is defined
        """
        if self.__credentials == "*":
            return True

        if username in self.__credentials:
            return True
        return False

    def check_pw(self, pw) -> bool:
        """
        Function to check if a password is defined
        """
        if self.__credentials == "*":
            return True

        if pw in self.__credentials.values():
            return True
        return False

    @abstractmethod
    def bind_service(self):
        """
        Abstract method that needs to be implemented by any child class.
        It should handle the binding to a port and establishing a listener.
        """

    @abstractmethod
    def handle_connections(self):
        """
        Abstract method that needs to be implemented by any child class.
        It should handle incoming connections.
        """