"""
The snmp Honeypot.
The approach for designing this Honeypot was taken and adapted from
https://github.com/qeeqbox/honeypots/blob/main/honeypots/snmp_server.py
"""

import traceback

from os import getenv

from scapy.error import Scapy_Exception
from scapy.layers.snmp import SNMP
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol

from base_honeypot import BaseHoneypot


class SNMPPot(BaseHoneypot):
    """
    Honeypot for SNMP
    """

    def __init__(self, download_urls):
        super().__init__(download_urls)
        self.log("SNMPPot class successfully initialized")

    def handle_connections(self):
        # not needed for SNMP
        pass

    def bind_service(self, port: int = 8000, interface: str = "127.0.0.1"):
        _main = self

        class CustomDatagramProtocol(DatagramProtocol):
            """
            Overwriting the datagram protocol for snmp support
            """

            def __init__(self):
                self.__ip = None
                self.__s_id = None
                super().__init__()

            def parse_snmp(self, data):
                """
                function to try to parse incoming data as snmp
                and then extract relevant data
                """
                try:
                    parsed = SNMP(data)
                    community = parsed.community.val
                    version = parsed.version.val
                    oids = " ".join([item.oid.val for item in parsed.PDU.varbindlist])
                except Scapy_Exception:
                    version = "Unknown"
                    community = "Unknown"
                    oids = "Unknown"
                return version, community, oids

            def datagramReceived(self, datagram, addr):
                """
                function that is called when a datagram is received
                """
                self.__ip = addr[0]
                self.__s_id = _main.get_id(self.__ip, "snmp")
                _main.session_log(
                    self.__s_id, "<New Connection>", "NEW CONNECTION", "snmp", self.__ip
                )
                version, community, oids = self.parse_snmp(datagram)
                user_in = f"version: {version}; community: {community}, oids: {oids}"
                _main.session_log(self.__s_id, user_in, "CLIENT", "snmp", self.__ip)
                try:
                    response = _main.get_llm_response(user_in, "snmp", self.__s_id)
                    _main.session_log(
                        self.__s_id, response, "SERVER", "snmp", self.__ip
                    )
                    self.transport.write(response.encode("utf-8"), addr)
                except Exception:
                    # catch all exceptions, even unexpected ones
                    # respond something to not seem suspicious
                    self.transport.write(b"Error", addr)

        ####################################
        # back to the level of bind_service
        try:
            reactor.listenUDP(
                port=port, protocol=CustomDatagramProtocol(), interface=interface
            )
            reactor.run()
            self.log(f"SNMPot is running and listening on {interface}:{port}")
        except Exception:
            # catch all unhandled exceptions
            self.log(traceback.format_exc(), "FATAL ERROR")


if __name__ == "__main__":
    snmp = SNMPPot(download_urls=False)
    snmp.bind_service(port=int(getenv("LISTENING_PORT", "8161")), interface=getenv("LISTENING_INTERFACE", "127.0.0.1"))
