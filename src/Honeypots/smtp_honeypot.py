"""
The smtp honeypot.
The approach for designing the SSH Honeypot was taken and adapted from
https://github.com/qeeqbox/honeypots/blob/main/honeypots/smtp_server.py
"""

import socket
import traceback

from base64 import b64decode
from os import getenv

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.mail.smtp import ESMTP

from base_honeypot import BaseHoneypot


class SMTPPot(BaseHoneypot):
    """
    Honeypot for SMTP
    """

    def __init__(self, download_urls):
        super().__init__(download_urls)
        self.log("SMTPPot class successfully initialized")

    def handle_connections(self):
        pass

    def bind_service(self, port: int = 8000, interface: str = "127.0.0.1"):
        _main = self

        class CustomSMTPProtocol(ESMTP):
            """
            Custom SMTP implementation based upon ESMTP
            """

            def __init__(self, *args, **kwargs):
                # placeholders for the clients ip and sessionID
                self.__ip = None
                self.__s_id = None

                domain_name = None
                try:
                    # override the domain name in the initialization of ESMPT
                    # this is done to prevent leaking the actual hostname!
                    # domain_name = socket.getfqdn()
                    socket.getfqdn = lambda: "ip-127-0-0-1.ec2.internal"
                    super().__init__(*args, **kwargs)
                finally:
                    if domain_name:
                        socket.getfqdn = domain_name

            def connectionMade(self):
                self.__ip = self.transport.getPeer().host
                self.__s_id = _main.get_id(self.__ip, "smtp")
                _main.session_log(
                    self.__s_id, "<New Connection>", "NEW CONNECTION", "smtp", self.__ip
                )
                super().connectionMade()

            def ext_AUTH(self, rest):
                """
                custom auth function
                """
                print(rest)
                if rest[0] == b"PLAIN":
                    _, username, password = (
                        b64decode(rest[1].strip())
                        .decode("utf-8", errors="replace")
                        .split("\0")
                    )
                    _main.session_log(
                        self.__s_id,
                        f"{username} - {password}",
                        "LOGIN",
                        "smtp",
                        self.__ip,
                    )
                    # accept all login combinations
                    self.sendCode(235, b"Authentication successful.")

            def do_EHLO(self, rest):
                """
                Custom EHLO function
                """
                self.sendCode(
                    250,
                    f"ip-127-0-0-1.ec2.internal Hello {rest}\n8BITMIME\nAUTH LOGIN PLAIN\nSTARTTLS".encode(),
                )

            def state_COMMAND(self, line):
                command, *rest = line.split(b" ")
                command = _main.convert_str(command)
                parsed_line = _main.convert_str(line)

                _main.session_log(self.__s_id, parsed_line, "CLIENT", "smtp", self.__ip)

                arg = rest[0] if rest else b""

                # handle basic commands
                if command.upper() == "EHLO":
                    return self.do_EHLO(arg)

                if command.upper() == "HELO":
                    return self.do_HELO(arg)

                if command.upper() == "QUIT":
                    return self.do_QUIT(arg)

                if command.upper() == "RSET":
                    return self.do_RSET(arg)

                if command.upper() == "AUTH":
                    return self.ext_AUTH(rest)

                # get LLM response for other commands
                try:
                    response = _main.get_llm_response(parsed_line, "smtp", self.__s_id)
                    _main.session_log(
                        self.__s_id, response, "SERVER", "smtp", self.__ip
                    )
                    # right now the response code is hard-codes
                    # in the future this could also be derived dynamically
                    self.sendCode(200, response.encode("utf-8"))
                    return ""
                except Exception:
                    # handle all exceptions by pretending to not know the command
                    return self.do_UNKNOWN(arg)

        class CustomSMTPFactory(Factory):
            """
            The wrapper class for the custom SMTP protocol
            """

            protocol = CustomSMTPProtocol
            portal = None

            def buildProtocol(self, addr):
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        ####################################
        # back to the level of bind_service
        try:
            factory = CustomSMTPFactory()
            reactor.listenTCP(port=port, factory=factory, interface=interface)
            reactor.run()
            self.log(f"SMTPPot is running and listening on {interface}:{port}")
        except Exception:
            # catch all uhandled exceptions
            self.log(traceback.format_exc(), "FATAL ERROR")


if __name__ == "__main__":
    smtp = SMTPPot(download_urls=False)
    smtp.bind_service(port=int(getenv("LISTENING_PORT", "8025")), interface=getenv("LISTENING_INTERFACE", "127.0.0.1"))
