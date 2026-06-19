"""
This is the file that actually takes in requests
from honeypots and then passes them along to the
llm_handler which communicates with the respective LLM API
"""
import secrets
import traceback

from flask import Flask, request, jsonify

from llm_handler import LLMHandler

#######################################
# UPDATE THIS FOR MORE PROTOCOL SUPPORT
PROTO_PROMPTS = {
    "ssh": "ssh_prompt.txt",
    "ftp": "ftp_prompt.txt",
    "http": "http_prompt.txt",
    "telnet": "telnet_prompt.txt",
    "ipp": "ipp_prompt.txt",
    "smtp": "smtp_prompt.txt"
}

# UPDATE THIS FOR DIFFERENT MODELS
# MODEL = "gpt-4.1-nano"
MODEL = "llama3.1"
PROVIDER = "ollama"
#######################################

app = Flask(__name__)
# set the secret key upon startup
app.secret_key = secrets.token_hex(32)

READY = False
READY_EXCEPTION = None
try:
    llm_handler = LLMHandler(PROTO_PROMPTS, MODEL, PROVIDER)
    READY = True
except Exception:
    # broad catching, but important to not error out
    # and instead catch all potential exceptions
    exc = traceback.format_exc()
    print("Error during init of llm handler")
    # print(exc)
    # save the exception as a string so it can be queried
    # with the is_ready path
    READY_EXCEPTION = exc


@app.route("/is_ready", methods=["GET"])
def is_ready():
    """
    Checking if the LLMHandler is ready and working
    If not then return the full exception so it can be logged
    """
    if READY:
        return_val = {"ready": True, "Exception-Info": "N/A"}
    else:
        return_val = {"ready": False, "Exception-Info": READY_EXCEPTION}
    return jsonify(return_val), 200


@app.route("/get_response", methods=["POST"])
def get_response():
    """
    Getting a response from the LLM
    """
    # If the application is not ready then abort
    if not READY:
        return jsonify({"ready": False}), 500

    # If this fails a code 400 will be returned!
    data = request.get_json(force=True)

    # Validate that all required keys are here
    missing_keys = []
    for key in ["protocol", "input", "session_id", "username"]:
        if not key in data:
            missing_keys.append(key)

    # If there are keys missing then return code 400
    if len(missing_keys) > 0:
        return jsonify({"Missing keys": missing_keys}), 400

    try:
        response = llm_handler.get_response(
            protocol=data["protocol"],
            user_in=data["input"],
            session_id=data["session_id"],
            username=data["username"]
        )
        return jsonify({"response":response}), 200
    except Exception:
        # return the exception so it can be logged
        # important to catch any kind of exception
        return jsonify({"Exception-Info":traceback.format_exc()}), 500
