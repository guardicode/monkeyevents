from typing import Sequence

from pydantic import Field

from monkeyevents.base_models import InfectionMonkeyModelConfig
from monkeyevents.credentials import Credentials

from ..credentials.encoding import SecretEncodingConfig
from . import AbstractAgentEvent


class CredentialsStolenEvent(AbstractAgentEvent):
    """
    An event that occurs when an agent collects credentials from the victim

    Attributes:
        :param stolen_credentials: The credentials that were stolen by an agent
    """

    stolen_credentials: Sequence[Credentials] = Field(default_factory=list)

    class Config(SecretEncodingConfig, InfectionMonkeyModelConfig):
        pass
