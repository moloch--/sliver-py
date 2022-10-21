from .pb.commonpb.common_pb2 import Request
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub

try:
    from typing import Protocol
except ImportError:
    from typing_extensions import Protocol


class PbWithRequestProp(Protocol):  # type: ignore
    """Protocol for protobuf with Request field"""

    @property
    def Request(self) -> Request:
        ...


class InteractiveObject(Protocol):  # type: ignore
    """Protocol for objects with interactive methods"""

    @property
    def timeout(self) -> int:
        ...

    @property
    def _stub(self) -> SliverRPCStub:
        ...

    def _request(self, pb: PbWithRequestProp) -> PbWithRequestProp:
        ...
