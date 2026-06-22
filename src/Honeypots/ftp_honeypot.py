"""
The ftp Honeypot.
The approach for designing this Honeypot was taken and adapted from
https://github.com/qeeqbox/honeypots/blob/main/honeypots/ftp_server.py
"""

import traceback

from contextlib import suppress
from os import getenv

from twisted.cred import portal, credentials
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.portal import Portal
from twisted.internet import reactor, defer
from twisted.protocols.ftp import (
    FTPAnonymousShell,
    FTPFactory,
    FTP,
    IFTPShell,
    AuthorizationError,
    USR_LOGGED_IN_PROCEED,
    CmdNotImplementedError,
)
from twisted.python import filepath
from zope.interface import implementer

from base_honeypot import BaseHoneypot


class FTPPot(BaseHoneypot):
    """
    Honeypot for FTP
    """

    def __init__(self, server_version, download_urls):
        self.__server_version = server_version
        super().__init__(download_urls)
        self.log("FTPPot class successfully initialized")

    def bind_service(self, port: int = 8000, interface: str = "127.0.0.1"):
        _main = self

        @implementer(portal.IRealm)
        class CustomFTPRealm:
            """
            Custom FTP Realm that provides access to the data folder
            that is created in the DockerfileFTP.
            Note: The directory is actually not used as the main
            FTP Implementation (CustomFTPProtocol) simulates all commands!
            """

            def __init__(self, filedir):
                self.anonymous_root = filepath.FilePath(filedir)

            def requestAvatar(self, _, __, *interfaces):
                for iface in interfaces:
                    if iface is IFTPShell:
                        avatar = FTPAnonymousShell(self.anonymous_root)
                        return (
                            IFTPShell,
                            avatar,
                            getattr(avatar, "logout", lambda: None),
                        )
                    raise NotImplementedError(
                        "Only IFTPShell interface is supported by this realm"
                    )

        @implementer(ICredentialsChecker)
        class CustomAccess:
            """
            Custom Access class that handles FTP authorization
            """

            credentialInterfaces = (
                credentials.IAnonymous,
                credentials.IUsernameHashedPassword,
            )

            def requestAvatarId(self, credentials):
                with suppress(Exception):
                    username = _main.convert_str(credentials.username)
                    password = _main.convert_str(credentials.password)
                    if _main.check_username(username) and _main.check_pw(password):
                        return defer.succeed(credentials.username)
                return defer.fail(UnauthorizedLogin())

        class CustomFTPProtocol(FTP):
            """
            Custom FTP Protocol implementation
            """

            def __init__(self):
                self.state = self.UNAUTH
                self.__username = None
                self.__ip = None
                self.__s_id = None
                super().__init__()

            def rawDataReceived(self, data):
                # abstract method that is not needed
                pass

            def connectionMade(self):
                # request a new or existing session_id
                self.__ip = self.transport.getPeer().host
                self.__s_id = _main.get_id(self.__ip, "ftp")
                # log the connection
                _main.session_log(
                    self.__s_id, "<New Connection>", "NEW CONNECTION", "ftp", self.__ip
                )

                self.state = self.UNAUTH
                self.setTimeout(self.timeOut)
                self.reply("220.2", self.factory.welcomeMessage)

            def ftp_PASS(self, password):
                """
                Overwriting the ftp_PASS function to customize authentication
                for the honeypot
                """
                # the username will always be already set
                username = _main.convert_str(self._user)
                password = _main.convert_str(password)
                _main.session_log(
                    self.__s_id, f"{username} - {password}", "LOGIN", "ftp", self.__ip
                )
                if _main.check_username(username) and _main.check_pw(password):
                    self.state = self.AUTHED
                    return USR_LOGGED_IN_PROCEED
                else:
                    self.state = self.UNAUTH
                    raise AuthorizationError

            def processCommand(self, cmd, *params):
                """
                Overwriting the actual processCommand function from the ftp protocol
                to allow for the integration of the LLM
                """
                # convert to string
                cmd = _main.convert_str(cmd)
                # params is a tuple that may contain multiple arguments
                arguments = []
                # parse all parts to a string and save in a list
                # since a tuple is not modifiable this needs to be a list
                for i in params:
                    arguments.append(_main.convert_str(i))
                # recreate a tuple from the arguments, forming the
                # actual command that the client invoked
                client_message = f"{cmd}{tuple(arguments)}"

                # log the command
                _main.session_log(
                    self.__s_id, client_message, "CLIENT", "ftp", self.__ip
                )
                # handle exit commands
                if cmd.upper() == "QUIT" or cmd.upper() == "BYE":
                    _main.session_log(
                        self.__s_id,
                        "<Connection Exit>",
                        "CONNECTION EXIT",
                        "ftp",
                        self.__ip,
                    )
                    return self.ftp_QUIT()
                # handle public feat command - no authentication required
                if cmd.upper() == "FEAT":
                    return self.ftp_FEAT()

                # handle auth states - get username
                if self.state == self.UNAUTH:
                    if cmd == "USER":
                        return self.ftp_USER(*params)
                    if cmd == "PASS":
                        return "503", "USER required before PASS"
                    return "530.1"  # Not logged in

                if self.state == self.INAUTH:
                    if cmd == "PASS":
                        self.state = self.AUTHED
                        return USR_LOGGED_IN_PROCEED
                        # return self.ftp_PASS(*params)
                    return "503", "PASS required after USER"

                if self.state == self.AUTHED:
                    # WCAT: detect curl/wget and dispatch to WCAT
                    import re, threading, os, requests as req
                    _dl_regex = re.compile(r'(?:curl|wget)\s+.*?(https?://[^\s;|&>]+)', re.IGNORECASE)
                    _dl_match = _dl_regex.search(client_message)
                    if _dl_match:
                        _dl_url = _dl_match.group(1)
                        _main.session_log(self.__s_id, f"DOWNLOAD DETECTED: {_dl_url}", "WCAT", "ftp", self.__ip)
                        self.sendLine(b"Downloading... [========================================] 100%")
                        def _send_to_wcat(url):
                            wcat_addr = os.environ.get("WCAT_HANDLER", None)
                            if wcat_addr:
                                try:
                                    req.post(f"http://{wcat_addr}/analyze", json={"urls": [url]}, timeout=5)
                                except Exception:
                                    pass
                        threading.Thread(target=_send_to_wcat, args=(_dl_url,), daemon=True).start()
                        return
                    response = _main.get_llm_response(
                        client_message, "ftp", self.__s_id, self.__username
                    )
                    _main.session_log(self.__s_id, response, "SERVER", "ftp", self.__ip)
                    self.sendLine(response.encode("utf-8"))
                    return

                # if nothing handles the command fallback to unkown command
                return defer.fail(CmdNotImplementedError(cmd))

        ####################################
        # back to the level of bind_service
        try:
            p = Portal(CustomFTPRealm("data/"), [CustomAccess()])
            factory = FTPFactory(p)
            factory.protocol = CustomFTPProtocol
            factory.welcomeMessage = self.__server_version
            reactor.listenTCP(port=port, factory=factory, interface=interface)
            reactor.run()
            self.log(f"FTPPot is running and listening on {interface}:{port}")
        except Exception:
            # general exception logging to catch all exceptions
            self.log(traceback.format_exc(), "FATAL ERROR")

    def handle_connections(self):
        # not needed for ftp handling
        pass


if __name__ == "__main__":
    ftp = FTPPot("ProFTPD 1.3.5", download_urls=False)
    ftp.bind_service(port=int(getenv("LISTENING_PORT", "8021")), interface=getenv("LISTENING_INTERFACE", "127.0.0.1"))
