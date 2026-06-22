"""
The telnet Honeypot.
The approach for designing this Honeypot was taken and adapted from
https://github.com/qeeqbox/honeypots/blob/main/honeypots/telnet_server.py
"""

import traceback

from os import getenv

from twisted.conch.telnet import TelnetProtocol, TelnetTransport
from twisted.internet import reactor
from twisted.internet.protocol import Factory

from base_honeypot import BaseHoneypot


class TelnetPot(BaseHoneypot):
    """
    Honeypot for telnet
    """

    def __init__(self, server_signature: str, server_name: str, download_urls: bool):
        self.signature = server_signature
        self.server_name = server_name
        super().__init__(download_urls)
        self.log("TelnetPot class successfully initialized")

    def bind_service(self, port: int = 8021, interface: str = "127.0.0.1"):
        _main = self

        class CustomTelnetProto(TelnetProtocol):
            """
            This class overwrites the telnet protocol class
            that is provided by twisted so that it becomes a honeypot.
            It needs to be inside the bind_service function
            so that it gets access to the internal logger functions.
            """

            def __init__(self):
                self.__s_id = None
                self._state = None
                self._user = None
                self._pass = None
                self.__ip = ""
                super().__init__()

            def __convert_str(self, string) -> str:
                """
                Internal helper function that checks
                if a string is in bytes and then tries to
                decode it and else just returns the str version
                """
                if isinstance(string, bytes):
                    # try to decode and replace invalid chars with placeholders
                    return string.decode("utf-8", errors="replace")
                return str(string)

            def connectionMade(self):
                # AI generated, but hardcoded welcome banner
                message = (
                    b"--------------------------------------------------------\r\n"
                    b"                ROUTER-128-JDI-MGMT                     \r\n"
                    b"--------------------------------------------------------\r\n"
                    b"Router Model: Cisco ISR 4331\r\n"
                    b"Firmware Version: 16.12.3\r\n"
                    b"Copyright (c) 2023 Cisco Systems, Inc. All rights reserved.\r\n"
                    b"\r\n"
                    b"This device is for authorized use only.\r\n"
                    b"Unauthorized access is prohibited and may be subject to \r\n"
                    b"criminal prosecution.\r\n"
                    b"\r\n"
                    b"Please enter your username and password to continue.\r\n"
                    b"--------------------------------------------------------\r\n"
                )
                self.transport.write(message)
                self.transport.write(b"Login: ")
                self._state = "Username"

                self.__ip = self.transport.getPeer().host
                self.__s_id = _main.get_id(self.__ip, "telnet")
                _main.session_log(
                    self.__s_id,
                    "<New Connection>",
                    "NEW CONNECTION",
                    "telnet",
                    self.__ip,
                )

            def connectionLost(self, reason=None):
                self._state = None
                self._user = None
                self._pass = None
                if not self.__s_id:
                    _main.session_log(
                        self.__s_id,
                        "<End Connection>",
                        "END CONNECTION",
                        "telnet",
                        self.__ip,
                    )

            def dataReceived(self, data):
                data = data.strip()
                if self._state == "Username":
                    self._user = self.__convert_str(data)
                    self._state = "Password"
                    self.transport.write(b"Password: ")
                elif self._state == "Password":
                    self._pass = self.__convert_str(data)
                    # log the credentials that were put in
                    if _main.check_username(self._user) and _main.check_username(
                        self._pass
                    ):
                        _main.session_log(
                            self.__s_id,
                            f"{self._user} - {self._pass}",
                            "LOGIN",
                            "telnet",
                            self.__ip,
                        )
                        self._state = "data"
                        self.transport.write(
                            f"{self._user}@{_main.server_name}$ ".encode("utf-8")
                        )
                    else:
                        _main.session_log(
                            self.__s_id,
                            f"{self._user} - {self._pass}",
                            "LOGIN-DENIED",
                            "telnet",
                            self.__ip,
                        )
                        self.transport.loseConnection()
                else:
                    user_in = self.__convert_str(data)
                    # log the user input
                    _main.session_log(
                        self.__s_id, user_in, "CLIENT", "telnet", self.__ip
                    )
                    if user_in == "exit":
                        self.transport.loseConnection()
                        _main.session_log(
                            self.__s_id,
                            "<Connection Exit>",
                            "CONNECTION EXIT",
                            "telnet",
                            self.__ip,
                        )
                    else:
                        try:
                            # WCAT: detect curl/wget and dispatch to WCAT
                            import re, threading, os, requests as req
                            _dl_regex = re.compile(r'(?:curl|wget)\s+.*?(https?://[^\s;|&>]+)', re.IGNORECASE)
                            _dl_match = _dl_regex.search(user_in)
                            if _dl_match:
                                _dl_url = _dl_match.group(1)
                                _main.session_log(self.__s_id, f"DOWNLOAD DETECTED: {_dl_url}", "WCAT", "telnet", self.__ip)
                                self.transport.write(b"Downloading... [========================================] 100%\r\n")
                                def _send_to_wcat(url):
                                    wcat_addr = os.environ.get("WCAT_HANDLER", None)
                                    if wcat_addr:
                                        try:
                                            req.post(f"http://{wcat_addr}/analyze", json={"urls": [url]}, timeout=5)
                                        except Exception:
                                            pass
                                threading.Thread(target=_send_to_wcat, args=(_dl_url,), daemon=True).start()
                                self.transport.write(f"{self._user}@ROUTER12$ ".encode("utf-8"))
                            else:
                                response = _main.get_llm_response(
                                    user_in, "telnet", self.__s_id, self._user
                                )
                                # log the response
                                _main.session_log(
                                    self.__s_id, response, "SERVER", "telnet", self.__ip
                                )
                                self.transport.write(f"{response}\r\n".encode("utf-8"))
                                self.transport.write(
                                    f"{self._user}@ROUTER12$ ".encode("utf-8")
                                )
                        except Exception:
                            # catch all exceptions
                            _main.session_log(
                                self.__s_id,
                                "Failed to get response",
                                "SERVER",
                                "telnet",
                                self.__ip,
                            )
                            _main.log(
                                "Error during the retrieval of a LLM response!", "ERROR"
                            )
                            _main.log(traceback.format_exc(), "ERROR")
                            self.transport.loseConnection()
        try:
            factory = Factory()
            factory.protocol = lambda: TelnetTransport(CustomTelnetProto)
            # linters may give an error for the next two lines despite them being correct
            # see also: https://stackoverflow.com/a/18712867
            reactor.listenTCP(port=port, factory=factory, interface=interface)
            reactor.run()
            self.log(f"TelnetPot is running and listening on {interface}:{port}")
        except Exception:
            # catch all remaining exceptions
            self.log(traceback.format_exc(), "FATAL ERROR")

    def handle_connections(self):
        # not needed for telnet handling
        pass


if __name__ == "__main__":
    telnet = TelnetPot(
        "GNU inetutils telnetd 2.0 (ported and patched 2022)",
        server_name="ROUTER12",
        download_urls=True,
    )
    telnet.bind_service(port=int(getenv("LISTENING_PORT", "8023")), interface=getenv("LISTENING_INTERFACE", "127.0.0.1"))
