import traceback
from datetime import datetime

import paramiko


def connect_to_server(hostname, port, username, password):
    try:
        # Create an SSH client
        client = paramiko.SSHClient()

        # Load system host keys
        # client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Set the policy to add the server's host key automatically
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the server
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
        )

        print(f"Successfully connected to {hostname}:{port}")

        # Optionally, you can execute a command
        stdin, stdout, stderr = client.exec_command(
            f"echo {datetime.today().strftime('%H:%M:%S')}", timeout=5
        )
        # print("Command output:", stdout.read().decode())
        # Stream stdout
        print("Output:", stdout.read().decode())

    except Exception as e:
        print(f"Failed to connect to {hostname}:{port} - {e}")
        print(traceback.format_exc())
    finally:
        # Close the connection
        client.close()


# Replace 'your_server_ip' and 'your_port' with the actual server IP and port
hostname = "127.0.0.1"
port = 8022  # Default SSH port
username = "test"
password = "test"

connect_to_server(hostname, port, username, password)
