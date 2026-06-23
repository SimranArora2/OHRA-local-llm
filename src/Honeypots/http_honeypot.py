"""
The http honeypot
"""

import secrets
import traceback

from flask import request, Response, Flask

from base_honeypot import BaseHoneypot


class HTTPPot(BaseHoneypot):
    """
    Honeypot for SSH
    """

    def __init__(self, server_header, download_urls):
        self.__server_header = server_header
        super().__init__(download_urls)
        # log that init checks succeeded
        self.log("HTTPPot class successfully initialized")

    def bind_service(self):
        # not needed for flask, needs to happen in wrapper
        pass

    def handle_connections(self, path="/"):
        """
        Handles incoming connections and requests a response from the LLM>
        """
        # ignore favicon requests
        if path == "favicon.ico":
            return "", 404
        request_data = request.get_json(force=True, silent=True)
        ip = request.remote_addr
        s_id = self.get_id(ip, "http")

        if request_data is None:
            # parsing failed since it was not json
            # fallback to the pure data
            request_data = request.get_data()
            try:
                request_data = request_data.decode()
            except UnicodeDecodeError:
                self.log(
                    f"Could not decode client request data [{s_id} - http]", "ERROR"
                )
                # strange binary content so set to empty string
                request_data = ""
        log_content = f"{request.method} -> /{path}: {request_data}"
        self.session_log(s_id, log_content, "CLIENT", "http", ip)

        try:
            user_input = f"{request.method} /{path}\n{request_data}"
            # WCAT: detect URLs in HTTP request body and dispatch
            import re, threading, os, requests as wcat_req
            _dl_regex = re.compile(r"(https?://[^\s;|&>'\"]+)", re.IGNORECASE)
            _dl_match = _dl_regex.search(str(request_data))
            if _dl_match:
                _dl_url = _dl_match.group(1)
                self.session_log(s_id, f"DOWNLOAD DETECTED: {_dl_url}", "WCAT", "http", ip)
                def _send_to_wcat(url):
                    wcat_addr = os.environ.get("WCAT_HANDLER", None)
                    if wcat_addr:
                        try:
                            wcat_req.post(f"http://{wcat_addr}/analyze", json={"urls": [url]}, timeout=5)
                        except Exception:
                            pass
                threading.Thread(target=_send_to_wcat, args=(_dl_url,), daemon=True).start()
            response = self.get_llm_response(
                user_in=user_input, protocol="http", session_id=s_id
            )
            self.session_log(s_id, response, "SERVER-RESPONSE", "http", ip)
            response = Response(response)
            response.headers["Server"] = self.__server_header
        except Exception:
            # general catching so that all potential errors are caught
            self.log(
                f"Could not get LLM response for: '{log_content}' [{s_id} - http]",
                "ERROR",
            )
            self.log(traceback.format_exc(), "ERROR")
            response = ""

        return response, 200


app = Flask(__name__)
http = HTTPPot("Dev-Server-12", download_urls=True)

# set the secret key upon startup
app.secret_key = secrets.token_hex(32)

# all http methods
HTTP_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
]


@app.route("/", defaults={"path": ""}, methods=HTTP_METHODS)
@app.route("/<path:path>", methods=HTTP_METHODS)
def catch_all(path):
    """
    function that catches all paths and methods
    """
    return http.handle_connections(path)
