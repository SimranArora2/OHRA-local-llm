"""
The SSH Honeypot.
The approach for designing this Honeypot was taken and adapted from
https://github.com/qeeqbox/honeypots/blob/main/honeypots/ssh_server.py
"""

import logging
import re
import socket
import threading
import traceback

from binascii import hexlify
from contextlib import suppress
from os import getenv
from _thread import start_new_thread

from io import StringIO
from threading import Event
from time import time

from paramiko import RSAKey, ServerInterface, Transport
from paramiko.common import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)
from paramiko.channel import Channel
from paramiko.ssh_exception import SSHException

from base_honeypot import BaseHoneypot


class SSHHandler(ServerInterface):
    """
    The SSH handler class. It is called for each connection
    and provides basic functionality by extending the ServerInterface
    class provided by Paramiko.
    It overwrites certain functions so that the Honeypot accepts
    any login credentials or keys, accepts connections in general and logs all input.

    When initializing this function the logger functions
    must be passed so that this class also has access to them
    and can log auth requests
    """

    def __init__(self, ip, port, session_id, main_class_handler: BaseHoneypot):
        self.ip = ip
        self.port = port
        self.event = Event()
        self.s_id = session_id
        self._main = main_class_handler
        self.__username = ""
        self.command = None
        self.shell_requested = False

    def check_channel_request(self, kind, *_, **__):
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        username = self._main.convert_str(username)
        password = self._main.convert_str(password)
        # store username for further reference
        self.__username = username
        if self._main.check_username(username) and self._main.check_pw(password):
            self._main.session_log(
                self.s_id, f"{username} - {password}", "LOGIN", "ssh", self.ip
            )
            return AUTH_SUCCESSFUL

        self._main.session_log(
            self.s_id, f"{username} - {password}", "LOGIN-DENIED", "ssh", self.ip
        )
        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        key = self._main.convert_str(hexlify(key.get_fingerprint()))
        self._main.session_log(
            self.s_id, f"{username} - {key}", "LOGIN-KEY", "ssh", self.ip
        )
        # disallow any public-key
        return AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        # a script will only request the execution but not send it via stdin!
        self.command = self._main.convert_str(command)
        self.event.set()
        return True

    def check_channel_shell_request(self, *_, **__):
        # a shell has been requested explicitly
        self.shell_requested = True
        self.event.set()
        return True

    def get_allowed_auths(self, *_, **__):
        # allow only password authentication - publickey auth is unrealistic
        # return "password,publickey"
        return "password"

    def check_channel_direct_tcpip_request(self, *_, **__):
        return OPEN_SUCCEEDED

    def check_channel_pty_request(self, *_, **__):
        return True

    def get_username(self) -> str:
        """
        Extra helper to return the username
        """
        return self.__username


class SSHPot(BaseHoneypot):
    """
    Honeypot for SSH
    """

    def __init__(self, server_version: str, server_name: str, download_urls: bool):
        # set paramiko logger to critical output only
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        self.server_sign = server_version
        self.__server_name = server_name
        # used for replacing ANSI SEQUENCES in input handling
        self.ansi_regex = re.compile(rb"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
        super().__init__(download_urls)
        self.log("SSHPot class successfully initialized")

    def __gen_keys(self) -> str:
        """
        Private helper function to generate a new RSA Key for the ssh server
        """
        key = RSAKey.generate(4098)
        # convert the key to a string
        string_key = StringIO()
        key.write_private_key(string_key)
        return string_key.getvalue()

    def bind_service(self, port: int = 8022, interface: str = "127.0.0.1"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((interface, port))
        sock.listen(1)
        private_key = self.__gen_keys()
        self.log(f"SSHPot is running and listening on {interface}:{port}")
        while True:
            try:
                client, _ = sock.accept()
                start_new_thread(self.handle_connections, (client, private_key))
            except Exception:
                # general exception to catch all errors
                self.log("Error during accepting of connection", "ERROR")
                self.log(traceback.format_exc(), "ERROR")

    def __parse_line(self, conn: Channel) -> str:
        """
        Private helper function that parses an incoming user input
        """
        user_in = b""
        # \x03 = CTRL_C
        while not any(user_in.endswith(char) for char in [b"\r", b"\n", b"\x03"]):
            conn.settimeout(30)
            recv = conn.recv(1024)
            # \x04 = CTRL_D
            if not recv or recv == b"\x04":
                conn.send(b"^D\r\n")
                raise EOFError
            # CTRL_C
            if recv == b"\x03":
                conn.send(b"^C\r\n")
            # new line (user input enter)
            elif recv == b"\r":
                conn.send(b"\r\n") #changed earlier b"\n"
            # ANSI Sequence
            elif recv == b"\x1b":
                # remove ansi sequences
                recv = self.ansi_regex.sub(b"", recv)

            # b"\x7f" = DEL
            if b"\x7f" in recv:
                # remove DEL
                recv.replace(b"\x7f", b"")

            if recv:
                user_in += recv
                conn.send(recv)
        return user_in.strip().decode(errors="replace")

    # regex to detect curl/wget commands with a URL
    __download_cmd_regex = re.compile(
        r'(?:curl|wget)\s+.*?(https?://[^\s;|&>]+)',
        re.IGNORECASE
    )

    def __extract_download_url(self, command: str):
        """
        If the command is a curl/wget with a URL, return the URL.
        Otherwise return None.
        """
        match = self.__download_cmd_regex.search(command)
        if match:
            return match.group(1)
        return None

    def __send_to_wcat(self, url: str, s_id: str, ip: str):
        """
        Dispatch URL to WCAT container for safe download + analysis.
        Non-blocking — runs in background thread.
        """
        import os
        import requests as req
        wcat_addr = os.environ.get("WCAT_HANDLER", None)
        if not wcat_addr:
            self.log("WCAT_HANDLER not set — skipping malware fetch", "INFO")
            return
        try:
            req.post(
                f"http://{wcat_addr}/analyze",
                json={"urls": [url], "session_id": s_id, "ip": ip},
                timeout=5,
            )
            self.log(f"Dispatched URL to WCAT: {url} [{s_id}]", "INFO")
        except Exception:
            self.log(f"Could not reach WCAT for URL: {url}", "ERROR")

    def __send_fake_download(self, conn: Channel, url: str):
        """
        Send a realistic fake curl download progress bar to the attacker.
        Makes the honeypot convincing — attacker thinks malware downloaded.
        """
        import time
        filename = url.split("/")[-1] or "malware"
        fake_size = 4096

        # Fake curl header
        conn.send(f"  % Total    % Received  % Xferd  Average Speed   Time    Time     Time  Current
".encode())
        conn.send(f"                                 Dload  Upload   Total   Spent    Left  Speed
".encode())

        # Animate progress bar
        for pct in [10, 25, 50, 75, 100]:
            received = int(fake_size * pct / 100)
            bar = "/" * (pct // 10)
            conn.send(
                f"{pct:3d} {fake_size:5d} {pct:3d} {received:5d}    0     0   2048      0  0:00:0{pct//25+1}  {bar}".encode()
            )
            time.sleep(0.4)

        conn.send(f"
100 {fake_size} 100 {fake_size}    0     0   2048      0  0:00:02
".encode())
        conn.send(f"///////////100% downloaded — saved as '{filename}'
".encode())

    def __send_llm_response(
        self, conn: Channel, s_id: str, ip: str, username: str, user_input: str
    ):
        """
        Private helper function to retrieve and send the LLM response
        """
        # get LLM response
        try:
            response = self.get_llm_response(user_input, "ssh", s_id, username)
        except RuntimeError:
            self.session_log(s_id, "Failed to get response", "SERVER", "ssh", ip)
            self.log(traceback.format_exc(), "FATAL ERROR")
            return

        # log the server response
        self.session_log(s_id, response, "SERVER", "ssh", ip)
        # send response
        conn.send(f"{response}\r\n".encode())  #replace("\n", "\r\n")- every line break is correct 

    def __handle_interactive(self, conn: Channel, s_id: str, ip: str, username: str):
        """
        Private helper function that handles interactive sessions
        """
        # welcome banner - AI Generated, but hardcoded for now
        # only send if the client is ready for this
        message = (
            "***********************************************************************\r\n"
            "*                          NOTICE TO USERS                            *\r\n"
            "***********************************************************************\r\n"
            "*                                                                     *\r\n"
            "*   You are accessing a development system maintained by the IT       *\r\n"
            "*   department. This server is running Ubuntu 22.04 LTS and is        *\r\n"
            "*   intended for authorized development and testing activities only.  *\r\n"
            "*                                                                     *\r\n"
            "*   All access and actions on this system are logged and monitored.   *\r\n"
            "*   Unauthorized access or misuse may result in disciplinary action   *\r\n"
            "*   and/or legal consequences.                                        *\r\n"
            "*                                                                     *\r\n"
            "*   By continuing to use this system, you acknowledge your consent    *\r\n"
            "*   to these terms.                                                   *\r\n"
            "*                                                                     *\r\n"
            "*   For support or questions, contact IT Support                      *\r\n"
            "***********************************************************************\r\n"
        )

        conn.send(message.encode("utf-8"))

        timeout = time() + 300
        while time() < timeout:
            conn.send(f"{username}@{self.__server_name}$ ")
            try:
                user_input = self.__parse_line(conn)
                # user_input = conn.recv(1024).decode(errors="replace").strip()
            except (TimeoutError, EOFError):
                break
            # log command
            self.session_log(s_id, user_input, "CLIENT", "ssh", ip)

            # handle exit command
            if user_input == "exit":
                self.session_log(
                    s_id, "<Connection Exit>", "CONNECTION EXIT", "ssh", ip
                )
                break

            # check if attacker is trying to download something
            dl_url = self.__extract_download_url(user_input)
            if dl_url:
                # log the detected URL
                self.session_log(s_id, f"DOWNLOAD DETECTED: {dl_url}", "WCAT", "ssh", ip)
                # send fake progress bar to attacker (blocking, so they see it)
                self.__send_fake_download(conn, dl_url)
                # dispatch real download to WCAT in background (non-blocking)
                thread = threading.Thread(
                    target=self.__send_to_wcat,
                    args=(dl_url, s_id, ip),
                    daemon=True
                )
                thread.start()
            else:
                # handle LLM response normally
                self.__send_llm_response(conn, s_id, ip, username, user_input)

    def handle_connections(self, client=None, key=None):
        try:
            ip, port = client.getpeername()
        except OSError:
            self.log("Error when trying to get IP and port of client", "ERROR")
            self.log(traceback.format_exc(), "ERROR")
            return

        session_id = self.get_id(ip, "ssh")
        self.session_log(session_id, "<New Connection>", "NEW CONNECTION", "ssh", ip)

        with Transport(client) as session:
            session.local_version = self.server_sign
            # load the newly generated RSA Key
            session.add_server_key(RSAKey(file_obj=StringIO(key)))
            ssh_handle = SSHHandler(ip, port, session_id, self)
            try:
                # start new session with client
                session.start_server(server=ssh_handle)
            except (SSHException, EOFError, ConnectionResetError):
                self.session_log(
                    session_id,
                    "Could not negotiate session with client!",
                    "SERVER-INFO",
                    "ssh",
                    ip,
                )
                return
            try:
                # handle the session
                with session.accept(30) as connection:
                    # wait 5s until exec or shell is requested
                    ssh_handle.event.wait(5)
                    if ssh_handle.command:
                        # only requested a command execution
                        # log command
                        self.session_log(
                            session_id, ssh_handle.command, "CLIENT", "ssh", ip
                        )
                        self.__send_llm_response(
                            connection,
                            session_id,
                            ip,
                            ssh_handle.get_username(),
                            ssh_handle.command,
                        )
                    elif ssh_handle.shell_requested:
                        # interactive shell requested
                        self.__handle_interactive(
                            connection, session_id, ip, ssh_handle.get_username()
                        )
                    else:
                        # nothing requested
                        self.session_log(
                            session_id,
                            "Client did not request shell or command!",
                            "SERVER-INFO",
                            "ssh",
                            ip,
                        )
                        return
                    with suppress(TimeoutError):
                        ssh_handle.event.wait(2)
            except TypeError:
                # this happens if no correct channel was established
                self.session_log(
                    session_id,
                    "No correct connection established",
                    "CONNECTION ERROR",
                    "ssh",
                    ip,
                )
            except Exception:
                # catch all other exceptions!
                self.log("Exception during ssh connection with client", "ERROR")
                self.log(traceback.format_exc(), "ERROR")


if __name__ == "__main__":
    ssh = SSHPot("SSH-2.0-OpenSSH_8.9", server_name="dev-server-08", download_urls=True)
    ssh.bind_service(port=int(getenv("LISTENING_PORT", "8022")), interface=getenv("LISTENING_INTERFACE", "127.0.0.1"))
