"""
This file injects collected malware commands into the
ssh or telnet honeypots and collects the responses
"""

import argparse
import json
import os
import sys
import time

from datetime import datetime

import requests

import pandas as pd


class Injector:
    """
    The injector class.
    Instantiation arguments:
    - command_path: str :- path to the dir/file holding the json files with the commands
    - target_port: int :- the port where the service is running (localhost:PORT)
    """

    def __init__(self, command_path: str, eventid_filter: list, llm_address: str):
        self.__llm = llm_address
        print(f"Reading data from {command_path}")
        # raw_data = self.__read_data(command_path, eventid_filter)
        self.__data = self.__read_new(command_path)
        print("Finished reading data")

        # get only unique commands (repeated commands are useless)
        # self.__data = []
        # unique_commands = set()
        # for entry in raw_data:
        #     if entry["input"] not in unique_commands:
        #         unique_commands.add(entry["input"])
        #         self.__data.append(entry)
        self.__count = len(self.__data)
        # print(
        #     f"Processed {len(raw_data)} commands, out of which {self.__count} are unique"
        # )

    def __selective_read(self, path: str, filter_eventids: list) -> list:
        """
        Private helper function to read and parse a file in a safe way
        """
        data = []
        try:
            with open(path, mode="r", encoding="utf-8") as f:
                # each line is an individual json item
                for line in f:
                    try:
                        json_item = json.loads(line)
                    except json.JSONDecodeError as exc:
                        if "cowrie.command.input" in line:
                            print("Error with:", path, "with line:", line)
                            raise exc
                        else:
                            continue
                    if json_item["eventid"] in filter_eventids:
                        data.append(json_item)
            return data
        except (IOError) as exc:
            print("Error with file:", path)
            raise exc

    def __read_data(self, path: str, event_filter: list) -> list:
        """
        Private helper function to read in the command data
        """
        raw_data = []
        if os.path.isdir(path):
            # handle a directory
            for file in os.listdir(path):
                if ".json" in file:
                    # only handle json files
                    file_path = os.path.join(path, file)
                    raw_data += self.__selective_read(file_path, event_filter)
        elif os.path.isfile(path) and ".json" in path:
            # handle only one file
            raw_data = self.__selective_read(path, event_filter)
        else:
            # no valid input
            raise FileNotFoundError(
                f"Provided path '{path}' is neither file nor folder!"
            )

        return raw_data
    
    def __read_new(self, path) -> list:
        if not os.path.isfile(path):
            raise FileNotFoundError("Given path was", path)
        with open(path, mode="r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def __get_llm_response(self, user_in, protocol, session_id):
        """
        Private helper function to get an LLM response
        """
        post_data = {
            "protocol": protocol,
            "input": user_in,
            "session_id": session_id,
            "username": "user1",
        }
        try:
            res = requests.post(
                f"{self.__llm}/get_response", json=post_data, timeout=20
            )
            res = res.json()["response"]
        except requests.exceptions.JSONDecodeError as exc:
            print("\n")
            print(f"Error with this request:\n{post_data}\nresponse:\n{res.text}")
            raise exc
        except KeyError as exc:
            print("\n")
            print(res.text)
            raise exc
        except requests.exceptions.RequestException:
            # catch all request exceptions that are not related to json decoding
            res = "NaN"

        return res

    def __update_status_bar(self, iteration, total, bar_length=40):
        """
        Private helper function for a status bar
        """
        # Calculate the percentage completion
        percent = iteration / total
        # Calculate the number of filled and unfilled characters
        filled_length = int(bar_length * percent)
        status_bar = "█" * filled_length + "-" * (bar_length - filled_length)

        # Print the status bar
        sys.stdout.write(f"\r|{status_bar}| {percent:.2%} Complete")
        sys.stdout.flush()

    def run_commands(self, mode: str):
        """
        Public function that runs the collected commands against the specified service
        Login will happen with user: TEST, pass: COMMANDS

        Progress bar is from: https://stackoverflow.com/a/3160819

        - mode: str :- either ssh or telnet to determine the mode
        """
        # dictionary for storing the input and outputs together
        in_out_data = {}
        timing_data = {}

        if not mode in ["ssh", "telnet"]:
            raise RuntimeError(
                f"Unsupported mode '{mode}'. Should be 'ssh' or 'telnet'"
            )

        start = time.time()
        counter = 0
        for command_entry in self.__data:
            # com = command_entry["input"]
            # session = command_entry["session"]
            com = command_entry[0]
            session = command_entry[1]
            # update status bar
            self.__update_status_bar(counter, self.__count)
            counter += 1

            # for logging the time it takes to get a response
            command_time = time.time()
            # get the response
            response = self.__get_llm_response(
                com, mode, session
            )
            # store the time it took to answer this command
            timing_data[com] = time.time() - command_time
            # store the input command and respective output
            in_out_data[com] = response

        print(f"\nTook {time.time() - start} seconds")

        # convert the in and outputs to a dataframe
        cols = ["input", "gen_output"]
        data = pd.DataFrame(data=in_out_data.items(), columns=cols)
        # add the timing data
        data["timing_data"] = timing_data.values()
        # save to excel file
        data.to_excel(f"{mode}-{datetime.now().strftime('%d-%m-%H-%M')}.xlsx")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Command Injector for ssh and telnet honeypots"
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to file or directory holding the commands",
    )
    parser.add_argument(
        "mode", type=str, help="The mode to run in", choices=["telnet", "ssh"]
    )
    args = parser.parse_args()
    inj = Injector(
        command_path=args.path,
        eventid_filter=["cowrie.command.input"],
        llm_address="http://127.0.0.1:7999",
    )
    inj.run_commands(args.mode)
