from ipaddress import IPv4Address

from monkeytypes import NetworkPort, PortStatus

from . import AbstractAgentEvent


class TCPScanEvent(AbstractAgentEvent):
    """
    An event that occurs when the Agent performs a TCP scan on a host

    Attributes:
        :param target: IP address of the scanned system
        :param ports: The scanned ports and their status (open/closed)
    """

    target: IPv4Address
    ports: dict[NetworkPort, PortStatus]
