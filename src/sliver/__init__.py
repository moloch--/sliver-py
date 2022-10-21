import os

from .beacon import InteractiveBeacon
from .client import SliverClient
from .config import SliverClientConfig
from .protobuf import client_pb2, common_pb2, sliver_pb2
from .session import InteractiveSession

__version__ = "0.0.18"


if os.getenv("HATCH_ENV_ACTIVE"):
    from rich import traceback

    traceback.install(show_locals=True)
