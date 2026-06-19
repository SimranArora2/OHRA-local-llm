"""
This is the first honeypot prototype

It communicates with the LLMHandler and LogHandler classes
via the wrappers, i.e. over http requests.

This prototype has the following more basic functionality:
- Listen on protocol level on specified ports
- Pass incoming requests to the LLMHandler to get a response
and send back that response
- Determine a session based upon the incoming IP Address
- Log everything

Compared to the prototype version 2 these are the major differences:
- No protocol specific handling implemented. Requests are more or less
directly passed along to the LLM model
- Prototype level 2 will implement some basic protocol specific behavior with
respective libraries and then only use the LLM for the "creative" part, i.e.
the part where the content of the response is generated. The LLM will, however,
take care of protocol specific stuff as little as possible
"""

from datetime import datetime
import json
import os
import signal
import selectors
import socket
import time
import traceback

import requests
    
class OHRAONE:
    """
    OHRA Prototype 1
    """

    def __init__(self):
        # variable that tracks whether sigint was received 
        self.__shutdown = False
        # setup the selectors which is important for handling multiple connections with sockets
        self.__sel = selectors.DefaultSelector()

        # read config values from environment
        # log_addr and llm_addr are easier to set during startup of
        # the docker container and are therefore not included in the conf file
        self.__log_addr = os.environ.get("LOG_HANDLER")
        self.__llm_addr = os.environ.get("LLM_HANDLER")
        # the conf file contains all the rest of the configuration, like
        # the mapping between services and ports etc.
        conf_file = os.environ.get("CONF_PATH")

        if self.__log_addr is None or self.__llm_addr is None or conf_file is None:
            # raise an error as we cannot work in this state!
            raise ValueError("LOG_HANDLER or LLM_HANDLER or CONF_PATH not specified!")

        # check and load config file
        if not os.path.isfile(conf_file):
            # raise an error as we cannot work in this state!
            raise FileNotFoundError(f"Provided path is: '{conf_file}'")
        try:
            with open(conf_file, mode="r", encoding="utf-8") as f:
                self.__config = json.load(f)
        except json.JSONDecodeError as exc:
            # logging is not yet established!
            print(f"Fatal error during loading of config file: '{conf_file}")
            raise exc

        # check that all expected keys are in the config file
        # this sanitization is important at startup to ensure
        # no sudden KeyError is raised later
        expected_keys = [
            "protocols",
            "rate_limit",
            "blacklist_path",
            "timeout",
            "sessionID_path",
        ]
        for k in expected_keys:
            if not k in self.__config:
                # logging is not yet established!
                raise KeyError(f"Missing key '{k}' in config file. Aborting!")

        # check that LogHandler and LLMHandler are available
        self.__check_available(self.__log_addr, "Log Handler")
        self.__check_available(self.__llm_addr, "LLM Handler")

        # dictionary that tracks current connections
        # and their last activity
        # structure:
        # { "conn-object" : ["last active timestamp","service (determined based upon port)"] }
        self.__connections = {}

        # dictionary for tracking how often an ip address has been seen during runtime
        # structure: { "ip-address" : <amount-of-connections> }
        # the rate limit of how often one ip address is allowed to connect
        # can be configured in the config.json file
        self.__ip_stats = {}

        # read the blacklist file if it exists
        # the blacklist file tracks blocked ip addresses
        blacklist = self.__read_files(self.__config["blacklist_path"], "blacklist")
        if len(blacklist) > 0 and isinstance(blacklist, list):
            self.__blacklist = blacklist
        else:
            self.__blacklist = []

        # dictionary that tracks sessionIDs
        # structure: {"ip-address":"session-id"}
        self.__session_ids = {}

        # read the session file if it exists
        session_ids = self.__read_files(
            self.__config["sessionID_path"], "sessionID list"
        )
        if len(session_ids) > 0 and isinstance(session_ids, dict):
            self.__session_ids = session_ids

        # log that init checks succeeded
        self.__log("Startup checks succeeded. Honeypot class is initialized")

    def __read_files(self, path, name):
        """
        Private helper function to read existing files
        """
        return_data = ""

        # check that path is defined
        if path is None or len(path.strip()) == 0:
            return return_data

        # check that the provided path exists
        if not os.path.isfile(path):
            self.__log(
                f"Provided path for {name} '{path}' does not exist",
                "WARNING",
            )
            return return_data

        # read the file and try to parse it
        with open(path, mode="r", encoding="utf-8") as f:
            try:
                return_data = json.load(f)
            except json.JSONDecodeError:
                self.__log(
                    f"Could not parse {name} '{path}' as json file",
                    "ERROR",
                )
        return return_data

    def __check_available(self, address, name):
        """
        Private helper function to check if the respective module is ready
        This is used to check whether the LogHandler and LLMHandler are initialized
        Note that this function is called when logging is potentially not yet established
        and thus this function raises errors directly, leading to a termination
        """
        # send request to the is_ready api
        try:
            res = requests.get(f"http://{address}/is_ready", timeout=10)
        except requests.exceptions.Timeout as exc:
            print(f"Request to {name} timed out!")
            raise exc
        except requests.exceptions.ConnectionError as exc:
            print(f"Request to {name} not possible!")
            raise exc


        # parse the response - should be json
        try:
            res = res.json()
        except requests.exceptions.JSONDecodeError as exc:
            print(f"Error during the handling of the check to {name}")
            raise exc

        # check if it is ready
        try:
            if not res["ready"]:
                raise RuntimeError(f"{name} is not ready! This is the response:\n{res}")
        except KeyError as exc:
            print(f"Response from {name} did not contain the key 'ready'!")
            raise exc

    def __log(self, content: str, event_type: str = "INFO"):
        """
        Private helper function to log application events (i.e. not session logs!)
        This communicates with the /event_log endpoint of the LogHandler (log_wrapper)
        """
        body = {
            "log_type": event_type,
            "timestamp": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
            "content": content,
        }
        res = requests.post(f"http://{self.__log_addr}/event_log", json=body, timeout=20)
        if res.status_code != 200:
            # do not abort but print to the system output so it is at least
            # somehow logged
            print("ERROR: Could not log a system event!")
            print(f"This was the event:\n{body}")
            try:
                print(f"This was the response:\n{res.json()}")
            except requests.exceptions.JSONDecodeError:
                # should not occur but better for proper sanitization
                print(f"This was the response:\n{str(res.content)}")

    def __session_log(
        self, session_id: str, content: str, event_type: str, protocol: str, ip: str
    ):
        """
        Private helper function to session events (i.e. not application logs!)
        This communicates with the /log endpoint of the log_wrapper
        """
        body = {
            "session_id": session_id,
            "log_type": event_type,
            "timestamp": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
            "protocol": protocol,
            "content": content,
            "ip": ip,
        }
        res = requests.post(f"http://{self.__log_addr}/log", json=body, timeout=20)
        if res.status_code != 200:
            print("ERROR: Could not log a session event!")
            print(f"This was the event:\n{body}")
            try:
                print(f"This was the response:\n{res.json()}")
            except requests.exceptions.JSONDecodeError:
                # should not occur but better for proper sanitization
                print(f"This was the response:\n{str(res.content)}")

    def __setup_socket(self, port):
        """
        Private helper function that sets up a socket and returns it
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        sock.setblocking(False)
        return sock

    def __conn_accept(self, sock, mask):
        """
        Private helper function that handles an incoming socket connection
        Adapted approach from https://docs.python.org/3.8/library/selectors.html#module-selectors
        """
        conn, _ = sock.accept()
        conn.setblocking(False)
        # get the remote ip
        remote_ip = conn.getpeername()[0]

        # determine the service based upon the port
        try:
            service = self.__config["protocols"][str(conn.getsockname()[1])]
        except KeyError:
            # fallback to the port itself
            service = str(conn.getsockname()[1])
            self.__log(f"Failed to determine service for port '{service}'", "ERROR")

        # log all incoming request incl. the ip address
        # this will include connections that are then blocked due to blacklisting
        # or rate-limiting
        self.__log(f"New connection: ({remote_ip}=>{service})")

        # IP blacklist checking
        if remote_ip in self.__blacklist:
            self.__log(f"Connection blocked due to blacklist: ({remote_ip})", "WARNING")
            conn.close()
            return

        # rate limit checking
        if remote_ip in self.__ip_stats:
            # Increment the stats for this ip address
            self.__ip_stats[remote_ip] += 1
            # if this IP address has been seen more than the configured rate limit
            # close the connection directly
            if self.__ip_stats[remote_ip] > self.__config["rate_limit"]:
                # blacklist this ip
                self.__blacklist.append(remote_ip)
                self.__log(
                    f"Connection blocked due to ratelimit: ({remote_ip})", "WARNING"
                )
                conn.close()
                return
        else:
            # first time that this ip is connecting
            self.__ip_stats[remote_ip] = 1

        # handle incoming data
        self.__sel.register(conn, selectors.EVENT_READ, self.__handle_conn)
        # register the connection for inactivity checks and further handling
        self.__connections[conn] = [time.time(), service]

    def __handle_conn(self, conn, mask):
        """
        Private helper function that handles incoming data
        """
        # check if IP was seen before --> request session content
        # if not: request new sessionID and save it
        remote_ip = conn.getpeername()[0]
        # the local port the connection connects to
        # this determines the service
        protocol = self.__connections[conn][1]

        prev_content = ""
        s_id = ""
        # check if this a re-occurring session, meaning that ip address and protocol match
        # a previous sessionID
        # a sessionID always contains the protocol before the minus
        if (
            remote_ip in self.__session_ids
            and protocol == self.__session_ids[remote_ip].split("-")[0]
        ):
            # fetch previous session content
            s_id = self.__session_ids[remote_ip]
            post_data = {"session_id": s_id}
            try:
                res = requests.post(
                    f"http://{self.__log_addr}/get_session", json=post_data, timeout=10
                )
                # catch exceptions and log them
                if res.status_code == 429:
                    # a 429 code is suspicious and means that someone attempted
                    # to enumerate session data and hit the rate limit in the LogHandler
                    # therefore
                    self.__log(str(res.json()), "WARNING")
                    self.__log(
                        f"Connection blocked due to ratelimit: ({remote_ip})", "WARNING"
                    )
                    self.__blacklist.append(remote_ip)
                    self.__sel.unregister(conn)
                    del self.__connections[conn]
                    conn.close()
                    return
                # any other non 200 codes
                if res.status_code != 200:
                    # not a fatal error - just means there is no prev. session content
                    self.__log(str(res.json()), "WARNING")
                else:
                    prev_content = res.json()["data"]
            except requests.exceptions.Timeout:
                # this is not a fatal error - most likely no prev. session content
                self.__log(traceback.format_exc(), "ERROR")
        else:
            # request new sessionID
            post_data = {"protocol": protocol}
            try:
                res = requests.post(
                    f"http://{self.__log_addr}/get_id", json=post_data, timeout=10
                )
                # handle non 200 code
                if res.status_code != 200:
                    # an error during sessionID generation is fatal as we need a sessionID
                    self.__log(str(res.json()), "FATAL ERROR")
                    self.__log(f"Closing connection due to fatal error with: {remote_ip}")
                    self.__sel.unregister(conn)
                    del self.__connections[conn]
                    conn.close()
                    return
                # 200 code is handled outside of try-except block
            except requests.exceptions.Timeout:
                # this is a fatal error as we need a sessionID for proper logging
                self.__log(traceback.format_exc(), "FATAL ERROR")
                self.__log(
                    f"Closing connection due to fatal error with: {remote_ip}",
                    "FATAL ERROR",
                )
                self.__sel.unregister(conn)
                del self.__connections[conn]
                conn.close()
                return
            # parse the response
            s_id = res.json()["id"]
            # save the new ID
            self.__session_ids[remote_ip] = s_id

        # receive data
        # corresponds to approx ~10mb
        data = conn.recv(10485760)
        if data:
            data = str(data.decode())
            # data is received
            # log the request
            self.__session_log(
                session_id=s_id,
                content=data,
                event_type="client",
                protocol=str(self.__connections[conn][1]),
                ip=str(remote_ip),
            )
            # send the request to the llm handler and then return back the response
            body = {
                "protocol": self.__connections[conn][1],
                "input": data,
                "session_content": prev_content,
            }
            try:
                res = requests.post(
                    f"http://{self.__llm_addr}/get_response", json=body, timeout=20
                )
                if res.status_code != 200:
                    # fatal error as something went wrong in the llm handler/wrapper
                    # this most likely will occur if either the openai api is down
                    # or if the token budget is used up
                    # or if a security exception in the openai api is raised, which would
                    # mean that the input contained something harmful or attempted prompt injection
                    self.__log(str(res.json()), "FATAL ERROR")
                    self.__log(
                        f"Closing connection due to fatal error with: {remote_ip}",
                        "FATAL ERROR",
                    )
                    # update session log
                    self.__session_log(
                        session_id=s_id,
                        content="<CONNECTION CLOSED>",
                        event_type="response",
                        protocol=self.__connections[conn][1],
                        ip=remote_ip,
                    )
                    self.__sel.unregister(conn)
                    del self.__connections[conn]
                    conn.close()
                    return
            except requests.exceptions.Timeout:
                # update session log
                self.__session_log(
                    session_id=s_id,
                    content="<CONNECTION CLOSED>",
                    event_type="response",
                    protocol=self.__connections[conn][1],
                    ip=remote_ip,
                )
                # fatal error since we did not get a response
                self.__log(traceback.format_exc, "FATAL ERROR")
                self.__log(
                    f"Closing connection due to fatal error with: {remote_ip}",
                    "FATAL ERROR",
                )
                self.__sel.unregister(conn)
                del self.__connections[conn]
                conn.close()
                return

            # get the actual response
            res = res.json()["response"]

            # log the response before sending it
            self.__session_log(
                session_id=s_id,
                content=res,
                event_type="response",
                protocol=self.__connections[conn][1],
                ip=remote_ip,
            )

            # send the response
            conn.send(res.encode("utf-8"))

            # update the last activity time stamp for this connection
            self.__connections[conn][0] = time.time()
        else:
            # update session log
            self.__session_log(
                session_id=s_id,
                content="<CONNECTION CLOSED>",
                event_type="client",
                protocol=self.__connections[conn][1],
                ip=remote_ip,
            )
            # session is terminated
            self.__log(
                f"Connection terminated by client: ({remote_ip},{self.__connections[conn][1]})"
            )
            self.__sel.unregister(conn)
            del self.__connections[conn]
            conn.close()

    def __check_timeouts(self):
        """
        Internal helper function that terminates sessions
        that have been idle for too long, therefore freeing resources.
        The timeout is configured in the config.json file
        """
        now = time.time()
        # cannot use .items() since this will lead to runtime errors as
        # this loop modifies the dictionary while iterating!
        for conn in list(self.__connections.keys()):
            if now - self.__connections[conn][0] > self.__config["timeout"]:
                # update session log
                remote_ip = conn.getpeername()[0]
                self.__session_log(
                    session_id=self.__session_ids[remote_ip],
                    content="<CONNECTION CLOSED>",
                    event_type="response",
                    protocol=self.__connections[conn][1],
                    ip=remote_ip,
                )
                self.__sel.unregister(conn)
                del self.__connections[conn]
                conn.close()
                self.__log(
                    f"Connection closed due to inactivity: ({remote_ip})"
                )

    def __save_items(self, name, obj):
        """
        Internal helper function that saves the blacklist and the sessionIDs
        """
        now = datetime.today().strftime("%Y-%m-%d_%H-%M")
        path = f"session_data/{name}-{now}.json"
        if len(obj) > 0:
            try:
                with open(path, mode="a", encoding="utf-8") as f:
                    json.dump(obj, f)
                self.__log(f"Successfully saved {name} under '{path}'")
            except (TypeError, IOError):
                self.__log(traceback.format_exc(), "ERROR")
                self.__log(f"Could not save {name}!", "ERROR")
                self.__log(f"This is the item that couldn't be saved:\n{obj}", "ERROR")

    def bind_ports(self):
        """
        Public function that binds the configured ports
        This is an adapted approach from
        https://docs.python.org/3.8/library/selectors.html#module-selectors
        """
        for port, service in self.__config["protocols"].items():
            self.__sel.register(
                self.__setup_socket(int(port)), selectors.EVENT_READ, self.__conn_accept
            )
            self.__log(f"Successfully setup '{service}' on port {port}")
        self.__log("OHRA1 has been setup and is listening")

    def __exit_gracefully(self, signum, frame):
        """
        function that handles the shutdown
        Unused args are needed since signal.signal provides two args
        """
        print("Received shutdown")
        self.__shutdown = True

    def run(self):
        """
        Public function that actually runs the application
        """
        # register signal for handling shutdown requests (SIGINT or SIGTERM)
        signal.signal(signal.SIGINT, self.__exit_gracefully)
        signal.signal(signal.SIGTERM, self.__exit_gracefully)

        try:
            while not self.__shutdown:
                events = self.__sel.select(timeout=1)
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)

                # check for timeouts to free resources
                self.__check_timeouts()
        except KeyboardInterrupt:
            self.__log("Received KeyboardInterrupt. Terminating application")
        except Exception:
            # handle any unexpected exceptions
            # this is important for proper logging
            self.__log(traceback.format_exc(), "FATAL ERROR")
            self.__log(
                "Unexpected Exceptions occurred. Terminating application", "FATAL ERROR"
            )
        finally:
            print("Goodbye")
            self.__log("Shutting down application...", "INFO")
            # Close connections that are still open
            for conn in self.__connections:
                self.__sel.unregister(conn)
                conn.close()
            # save the blacklist and sessionIDs if applicable
            self.__save_items("blacklist", self.__blacklist)
            self.__save_items("sessions", self.__session_ids)
            self.__log("Connections cleaned successfully - Goodbye", "INFO")

def main():
    """
    The main function and entrypoint of this file
    """
    # wait three seconds since the other two services need to properly startup first
    time.sleep(3)
    hp = OHRAONE()
    hp.bind_ports()
    hp.run()


if __name__ == "__main__":
    main()
