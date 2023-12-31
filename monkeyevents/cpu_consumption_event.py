from typing import Annotated

from monkeytypes import Percent
from pydantic import Field

from . import AbstractAgentEvent


class CPUConsumptionEvent(AbstractAgentEvent):
    """
    An event that occurs when the Agent consumes significant CPU resources for its own purposes.

    Attributes:
        :param utilization: The percentage of the CPU that is utilized
        :param cpu_number: The number of the CPU core that is utilized
    """

    utilization: Percent
    cpu_number: Annotated[int, Field(ge=0, strict=True)]
