"""
The Internet Printing Protocol (IPP) Honeypot.
The approach for designing this Honeypot is based upon flask
since IPP is based upon http
"""

import secrets
import traceback

from flask import request, Response, Flask

from base_honeypot import BaseHoneypot


class IPPPot(BaseHoneypot):
    """
    Honeypot for ipp (internet printing protocol)
    """

    def __init__(self, server_header, download_urls):
        self.__server_header = server_header
        super().__init__(download_urls)
        self.log("IPPPot class successfully initialized")

    def bind_service(self):
        # not needed for flask, needs to happen in wrapper
        pass

    def handle_connections(self, path="/"):
        """
        Handles incoming connections and requests a response from the LLM
        """
        # ignore favicon requests
        if path == "favicon.ico":
            return "", 404

        ip = request.remote_addr
        # decode IPP request data
        try:
            request_data = request.data.decode("utf-8")
        except UnicodeDecodeError:
            # could not decode IPP data, so must be a bad request
            return "", 400

        # request sessionID
        s_id = self.get_id(ip, "ipp")
        log_content = f"{request.method} -> /{path}: {request_data}"
        self.session_log(s_id, log_content, "CLIENT", "ipp", ip)

        try:
            user_input = f"{request.method} /{path}\n{request_data}"
            response = self.get_llm_response(user_input, "ipp", s_id)
            self.session_log(s_id, response, "SERVER", "ipp", ip)
            response = Response(response.encode("utf-8"))
            response.headers["Server"] = self.__server_header
            response.content_type = "application/ipp"
            return response, 200
        except Exception:
            # general catching needed to catch all kinds of errors
            self.log(
                f"Could not get LLM response for: '{log_content}' [{s_id} - ipp]",
                "ERROR",
            )
            self.log(traceback.format_exc(), "ERROR")
            # error when generating a response
            return "", 500


app = Flask(__name__)
ipp = IPPPot("IPP-Print-Server/1.0", download_urls=False)

# set the secret key upon startup
app.secret_key = secrets.token_hex(32)


# allow all paths but restrict to POST for IPP
@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def catch_all(path):
    """
    function that catches all paths and methods
    """
    return ipp.handle_connections(path)
