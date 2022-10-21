from typing import Protocol

from .pb.commonpb.common_pb2 import Request
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub


class PbWithRequestProp(Protocol):
    """Protocol for protobuf with Request field"""

    @property
    def Request(self) -> Request:
        ...


class InteractiveObject(Protocol):
    """Protocol for objects with interactive methods"""

    @property
    def timeout(self) -> int:
        ...

    @property
    def _stub(self) -> SliverRPCStub:
        ...

    def _request(self, pb: PbWithRequestProp) -> PbWithRequestProp:
        ...
