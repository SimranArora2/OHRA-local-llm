"""
This file holds the LogEntry class
which specifies how a log entry needs to look like
"""


class GeneralLogEntry:
    """
    This class specifies how a log entry should look like
    for general application events (i.e. not honeypot events)
    """

    def __init__(self, log_type: str, time: str, content: str):
        self._type = log_type
        self._time = time
        self._content = content

    def get_type(self) -> str:
        """
        Public getter function for the log type
        """
        return self._type

    def get_time(self) -> str:
        """
        Public getter function for the log time
        """
        return self._time

    def get_content(self) -> str:
        """
        Public getter function for the log content
        """
        return self._content

    def to_str(self) -> str:
        """
        Public function to get the log entry as one string
        """
        line = f"{self._time} {self._type}: {self._content}"
        return line

    def to_json(self) -> dict:
        """
        Public function to get the log entry as a dictionary element
        """
        elem = {
            "time": self._time,
            "type": self._type,
            "content": self._content,
        }
        return elem


class HoneyLogEntry(GeneralLogEntry):
    """
    This class specifies how a log entry should look like for an event from a honeypot
    It extends the general log entry class
    """

    def __init__(self, log_type: str, time: str, protocol: str, content: str, ip: str):
        self.__protocol = protocol
        self.__ip = ip
        super().__init__(log_type, time, content)

    def get_proto(self) -> str:
        """
        Public getter function for the protocol type
        """
        return self.__protocol

    def to_str(self) -> str:
        """
        Public function to get the log entry as one string
        """
        line = f"{self._time} [{self.__ip}-{self.__protocol}] {self._type}: {self._content}"
        return line

    def to_json(self) -> dict:
        """
        Public function to get the log entry as a dictionary element
        """
        elem = {
            "time": self._time,
            "type": self._type,
            "ip": self.__ip,
            "protocol": self.__protocol,
            "content": self._content,
        }
        return elem
