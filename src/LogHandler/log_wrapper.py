"""
This file contains the log wrapper.
It handles all requests to the log_handler via a flask api
"""

import os
import secrets
import traceback
import threading

from flask import Flask, request, jsonify

from log_handler import LogHandler

app = Flask(__name__)
# set the secret key upon startup
app.secret_key = secrets.token_hex(32)

READY = False
READY_EXCEPTION = None
try:
    logger = LogHandler(
        rate_limit=int(os.environ.get("rate_limit", "100")),
        rate_reset=int(os.environ.get("rate_reset", "900")),
    )
    READY = True
except Exception:
    # broad catching, but important to not error out
    # and instead catch all potential exceptions
    exc = traceback.format_exc()
    print("Error during init of log handler")
    # print(exc)
    # save the exception as a string so it can be queried
    # with the is_ready path
    READY_EXCEPTION = exc


@app.route("/is_ready", methods=["GET"])
def is_ready():
    """
    Checking if the LogHandler is ready and working
    If not then return the full exception so it can be logged
    """
    if READY:
        return_val = {"ready": True, "Exception-Info": "N/A"}
    else:
        return_val = {"ready": False, "Exception-Info": READY_EXCEPTION}
    return jsonify(return_val), 200


@app.route("/get_id", methods=["POST"])
def get_id():
    """
    Get a new session id
    Required method is post with json content
    Required key is "protocol"
    Optional key is "timeout", default is 3 seconds
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)

    # Validate that all required keys are here
    missing_keys = []
    for key in ["protocol"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    # apply the optional timeout argument but only if it exists
    try:
        timeout = data["timeout"]
        new_id = logger.gen_session_id(data["protocol"], timeout)
    except KeyError:
        new_id = logger.gen_session_id(data["protocol"])

    response = {"id": new_id}

    return jsonify(response), 200


@app.route("/get_session", methods=["POST"])
def get_session():
    """
    MOST LIKELY NO LONGER NEEDED - LEGACY FUNCTION
    Get the content of an existing session, identified
    by the session_id
    Required method is post with json content
    Required key is "session_id"

    Note that this function is rate limited.
    For more info on the rate limiting see log_handler.gen_session_id()
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)
    # Validate that all required keys are here
    missing_keys = []
    for key in ["session_id"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    try:
        session_data = logger.get_session(data["session_id"])
        return jsonify({"data": session_data}), 200
    except ConnectionRefusedError:
        response = {"Error": "Connection refused", "Reason": "Rate limit exceeded"}
        # this should then be logged but from the honeypot, as only the honeypot
        # knows the origin IP address
        return jsonify(response), 429
    except FileNotFoundError:
        response = {
            "Error": "File not found",
            "Reason": "Provided session id does not have existing logs",
        }
        # this should then be logged but from the honeypot, as only the honeypot
        # knows the origin IP address
        return jsonify(response), 404
    except Exception:
        response = {"Error": "Unknown", "Reason": traceback.format_exc()}
        return jsonify(response), 500


@app.route("/log", methods=["POST"])
def log():
    """
    Log something from a honeypot session.
    Required method is post with json content
    Required keys are
    - "session_id"
    - "log_type"
    - "timestamp"
    - "protocol"
    - "content"
    - "ip"
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)
    # Validate that all required keys are here
    missing_keys = []
    for key in ["session_id", "log_type", "timestamp", "protocol", "content", "ip"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    logger.log(
        session_id=data["session_id"],
        log_type=data["log_type"],
        timestamp=data["timestamp"],
        proto=data["protocol"],
        content=data["content"],
        ip=data["ip"],
    )
    response = {"Success": True}
    return jsonify(response), 200


@app.route("/event_log", methods=["POST"])
def event_log():
    """
    Log something from a the application.
    Required method is post with json content
    Required keys are
    - "log_type"
    - "timestamp"
    - "content"
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)
    # Validate that all required keys are here
    missing_keys = []
    for key in ["log_type", "timestamp", "content"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    logger.event_and_error(
        data["log_type"],
        data["timestamp"],
        data["content"],
    )
    response = {"Success": True}
    return jsonify(response), 200


@app.route("/process_urls", methods=["POST"])
def process_urls():
    """
    Function to download urls that were detected
    and save the response content
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)
    # Validate that all required keys are here
    missing_keys = []
    for key in ["urls"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    # start the handling of the urls in a non-blocking way
    thread = threading.Thread(target=logger.request_url, args=(data["urls"],))
    thread.start()

    # 202 indicates that it was accepted but not yet completed,
    # but therefore also not blocking the caller
    response = {"Success": True}
    return jsonify(response), 202
