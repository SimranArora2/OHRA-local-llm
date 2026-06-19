"""
This script executes the provided ssh and telnet commands
on a real system and captures all output

IMPORTANT: DO NOT RUN THIS ON YOUR ACTUAL SYSTEM
As a safety measures this script will ask to write CONFIRM
in the beginning before actually executing the commands!
"""

import json
import os
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import check_output, STDOUT, CalledProcessError, TimeoutExpired


def load_data(filepath: str) -> list:
    """
    function to load the json file and return all commands
    as a list
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError("Given path was", filepath)

    try:
        with open(filepath, mode="r", encoding="utf-8") as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as exc:
        print("Error with", filepath)
        raise exc

    return data


def run_command(command: str) -> list:
    """
    Helper function to run a command
    Used for multiprocessing
    """
    start_time = time.time()
    try:
        shell_output = check_output(
            command,
            shell=True,
            text=True,
            stderr=STDOUT,
            timeout=5,
            executable="/bin/bash",
        )
    except CalledProcessError as exc:
        # a non-0 return code
        shell_output = exc.output
    except TimeoutExpired:
        # timeout
        shell_output = "-"
    except Exception:
        # all other exceptions - to avoid aborting the program
        shell_output = "N/A"
    return [shell_output, time.time() - start_time]


def main(command_filepath: str, output_path: str, multi_flag: bool = False):
    """
    Main entry point of this script
    When setting multi_flag to True, multiprocessing will be used.
    This significantly speeds up the execution time!
    """
    data = load_data(command_filepath)

    print("#" * 20)
    print("ATTENTION!")
    print("#" * 20)
    print(
        "You are about to execute most-likely dangerous commands on the system directly"
    )
    print("This should only be done on an isolated VM!\n")
    try:
        conf = input("Please write 'CONFIRM' to proceed")
    except EOFError:
        conf = ""

    if conf != "CONFIRM":
        print("=> Aborting")
        return

    results_dir = {}
    command_amount = len(data)
    print(f"Starting execution of {command_amount} commands")

    if not multi_flag:
        counter = 0
        for command in data:
            # time the data
            start_time = time.time()

            # add support for different format
            # that also has the session information
            if isinstance(command, list):
                command = command[0]

            # execute the command
            try:
                shell_output = check_output(
                    command,
                    shell=True,
                    text=True,
                    stderr=STDOUT,
                    encoding="utf-8",
                    timeout=5,
                    executable="/bin/bash",
                )
            except CalledProcessError as exc:
                # if bash returns a non 0 return code this is still a valid output
                shell_output = exc.output
            except TimeoutExpired:
                # there are some commands that will execute an interactive command
                # this would result in no output on stdout so just raise a timeout
                # and set this to empty - comparable to an LLM output
                shell_output = ""

            # calculate timing
            duration = time.time() - start_time

            # save shell output and timing data
            results_dir[command] = [shell_output, duration]
            counter += 1
            sys.stdout.write(f"\r|{counter}/{command_amount}|")
            sys.stdout.flush()
    else:
        # multiprocessing approach
        print("INFO: multiprocessing selected")
        with ThreadPoolExecutor() as executor:
            # approach if using list without session information
            jobs = {executor.submit(run_command, command): command for command in data}

            # approach if using list with session information
            # jobs = {executor.submit(run_command, command[0]): command[0] for command in data}

            for future in as_completed(jobs):
                # cmd_in is the input command
                cmd_in = jobs[future]
                # cmd_results = [shell_output, duration]
                cmd_results = future.result()
                # save the input and output combination in the results dictionary
                results_dir[cmd_in] = cmd_results

    print("#" * 20)
    print("Finished running all commands")
    with open(output_path, mode="w", encoding="utf-8") as f:
        json.dump(results_dir, f)

    print("Saved all output under", output_path)


if __name__ == "__main__":
    try:
        path = sys.argv[1]
        main(path, "commands_out.json")
    except IndexError:
        print("Please provide the path to the json file holding the commands")
