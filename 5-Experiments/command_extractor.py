"""
Script to extract all relevant commands from the cowrie logs
"""

import json
import os
import sys


def load_file(filepath: str, all_commands: list) -> list:
    """
    Function to load the cowrie logs and get the commands
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError("Given path was", filepath)

    with open(filepath, mode="r", encoding="utf-8") as f:
        for line in f:
            if not "cowrie.command.input" in line:
                # ignore unimportant lines
                continue
            try:
                json_line = json.loads(line)
                all_commands.append([json_line["input"], json_line["session"]])
            except json.JSONDecodeError as exc:
                print("Error with line", line)
                raise exc

    return all_commands


def main(top_level_dir: str, out: str, mode: str):
    """
    Main entry point of this script
    """
    if os.path.isfile(out):
        raise FileExistsError("Given out path:", out)

    if not os.path.isdir(top_level_dir):
        raise FileNotFoundError("Given dir was", top_level_dir)

    data = []
    for honeypot_dir in os.listdir(top_level_dir):
        if os.path.isdir(os.path.join(top_level_dir, honeypot_dir)):
            if mode not in honeypot_dir:
                # ignore telnet/ssh dirs depending on the selected mode
                continue
            print(f"Processing {honeypot_dir}", end="...")
            for file in os.listdir(os.path.join(top_level_dir, honeypot_dir)):
                # only include json files
                if not "json" in file:
                    continue
                data = load_file(os.path.join(top_level_dir, honeypot_dir, file), data)
            print("Done")
    print("Extracted all commands")

    # keep only unique commands and drop exact duplicates
    unique_commands = set()
    commands_list = []
    for c in data:
        if c[0] not in unique_commands:
            unique_commands.add(c[0])
            commands_list.append(c)

    print(
        f"There are {len(commands_list)} unique commands out of {len(data)} that will be kept"
    )

    # save all commands in one big json file
    with open(out, mode="w", encoding="utf-8") as f:
        json.dump(commands_list, f)
    print("Saved commands under", out)


if __name__ == "__main__":
    try:
        dir_path = sys.argv[1]
        # main(dir_path, "telnet_all_commands.json", "telnet")
        main(dir_path, "telnet_all_commands_sessions.json", "telnet")
    except IndexError:
        print("Please provide the path as first argument")
