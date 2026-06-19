"""
This file contains the class that handles all logs.
"""

import hashlib
import json
import os
import time

from datetime import date
from secrets import token_urlsafe
from urllib.parse import urlparse, urlunparse
from urllib.error import URLError

from log_entry import GeneralLogEntry, HoneyLogEntry

import requests


class LogHandler:
    """
    This is the log handler class.
    Specifically it can do the following:
    - save session logs (sessions are identified by a specific, random session string)
    - return session logs given a specific random session string (guessing is rate limited)
    - generate a new session string for a new session
    - save error logs (from any application part)
    """

    def __init__(
        self,
        rate_limit: int,
        rate_reset: int,
    ):
        # ensure the directories exist
        if not os.path.isdir("session_logs"):
            raise KeyError("session_logs dir is missing!")
        if not os.path.isdir("error_logs"):
            raise KeyError("error_logs dir is missing!")
        if not os.path.isdir("downloaded_content"):
            raise KeyError("downloaded_content dir is missing!")

        self.__session_dir = "session_logs"
        self.__error_dir = "error_logs"
        self.__data_dir = "downloaded_content"
        # set the token len to 16 bytes initially
        self.__token_len = 16

        self.__last_reset = time.time()
        self.__invalid_attempts = 0
        self.__rate_limit = rate_limit
        self.__reset_duration = rate_reset

    def gen_session_id(self, proto: str, timeout: int = 3) -> str:
        """
        Public function that generates a new session id
        for a given protocol
        The session id is composed like this:
        - {protocol}-{random-token}

        The function ensures that the specific session id
        does not exist yet, since it will be used to save all logs

        The timeout specifies after what amount of search time
        the length of a token gets increased, i.e. if after
        X amount of seconds no unique token was found then
        the length of the token is increased by 16 bytes
        to get a larger possible space of token-names.
        This state is then saved as long as the log handler runs
        """
        # get the existing session identifiers
        existing_ids = os.listdir(self.__session_dir)

        # generate an initial session id
        session_id = f"{proto}-{token_urlsafe(16)}"

        start_t = time.time()

        # if the session id already exists then
        # try to generate a new one until a unique one is found
        while f"{session_id}.json" in existing_ids:
            # if after 3 seconds no unique id was found
            # extend the token len by 16 bytes
            # to increase the space of possible tokens
            if time.time() - start_t > timeout:
                start_t = time.time()
                self.__token_len += 16
            session_id = f"{proto}-{token_urlsafe(self.__token_len)}"

        return session_id

    def get_session(self, session_id) -> list:
        """
        MOST LIKELY NO LONGER NEEDED - LEGACY FUNCTION
        Public function to get the session content given a specific session id.

        This function is rate limited to prevent brute-forcing!
        By default it counts all invalid attempts in 15min time windows and
        then blocks all future requests if they exceed 100 invalid requests.
        The time window and request limit can be changed during init of this class.

        Note that the tokens are generated using the secure.token_urlsafe function
        """
        # check if the rate limit can be reset (default is after 15mins)
        if time.time() - self.__last_reset > self.__reset_duration:
            self.__last_reset = time.time()
            self.__invalid_attempts = 0

        # check if the rate limit has been exceeded
        if self.__invalid_attempts > self.__rate_limit:
            raise ConnectionRefusedError("Rate limit exceeded")

        # check if the specified session id exists
        filepath = os.path.join(self.__session_dir, f"{session_id}.json")
        if not os.path.isfile(filepath):
            self.__invalid_attempts += 1
            raise FileNotFoundError(f"Provided session id: '{session_id}.json'")

        with open(filepath, mode="r", encoding="utf-8") as f:
            # session_data is a json object
            # in python this is however represented as a list containing dict objects
            session_data = json.load(f)

        # retrieve the commands, everything else is not important for the LLM context
        # giving the LLM everything would also potentially leak IP information
        prev_commands = []
        for entry in session_data:
            # limit to the input of the client and do not include responses
            if entry["type"] == "client":
                prev_commands.append(entry["content"])

        # reduce the content in case it gets really large
        # otherwise issues with the LLM might occur
        prev_commands = prev_commands[-25:]

        return prev_commands

    def log(
        self,
        session_id: str,
        log_type: str,
        timestamp: str,
        proto: str,
        content: str,
        ip: str,
    ):
        """
        Public function to log the contents of a specific session.
        If the session had previous log entries the respective log will be
        extended.
        The existing log entries will be read in and then extended.
        Only this way is it guaranteed that the json structure is not corrupted!
        """
        log = HoneyLogEntry(log_type, timestamp, proto, content, ip)

        filepath = os.path.join(self.__session_dir, f"{session_id}.json")
        # read potential existing log content so it can be extended
        # since we need to work with json, this is the only possible approach
        # simply appending might corrupt the json structure
        if os.path.isfile(filepath):
            with open(filepath, mode="r", encoding="utf-8") as f:
                full_log = json.load(f)  # existing_log is a list
        else:
            full_log = []

        # overwrite with the newly added log
        full_log.append(log.to_json())
        with open(filepath, mode="w", encoding="utf-8") as f:
            json.dump(full_log, f)

    def event_and_error(self, log_type: str, timestamp: str, content: str):
        """
        Public function to log events and errors that occur during the run of the
        whole OHRA application, i.e. events and errors from honeypots and llm handlers
        arrive here as well.

        A new log file is created each day so that in the end there will be one
        event and error log file per day.
        """
        # get the current day and determine the filepath
        filepath = os.path.join(self.__error_dir, f"{date.today()}.log")

        log = GeneralLogEntry(log_type, timestamp, content)

        # write the new log entry
        # in append mode this ensures that in the case of existing log entries
        # these are not overwritten
        # if not log file exists this just creates a new file
        with open(filepath, mode="a", encoding="utf-8") as f:
            f.write(log.to_str())
            f.write("\n")

    def request_url(self, urls: list):
        """
        Public function to request an url.
        Note that this is important to receive potential exploits.
        Note further that it is recommended to run this with a
        DNS-resolver that blocks potential known (!) malicious sites
        like for example quad-dns!
        """
        # set a fake header - AI Generated
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        }
        # go through all urls
        try:
            for i in urls:
                # split the url to remove any unsafe parts
                # the purpose is to only keep the main url part
                # and to remove any potential unsafe additions
                # to an url
                parsed_url = urlparse(i)
                safe_url = urlunparse(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        "",  # no parameters
                        "",  # no queries
                        "",  # no fragments
                    )
                )
                response = requests.get(safe_url, headers=headers, timeout=20)

                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    extension = ""

                    if "image" in content_type:
                        extension = ".jpg"
                    elif "text" in content_type:
                        extension = ".txt"
                    elif "application" in content_type:
                        extension = ".bin"
                    else:
                        extension = ".DATA"

                    filename = (
                        f"{hashlib.sha256(response.content).hexdigest()}.{extension}"
                    )
                    filepath = os.path.join(self.__data_dir, filename)

                    with open(filepath, mode="wb") as f:
                        f.write(response.content)
        except (requests.RequestException, IOError, URLError):
            # ignore exceptions as this is not critical
            pass
