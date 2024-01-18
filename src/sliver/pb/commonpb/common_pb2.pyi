"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions
from builtins import (
    bool,
    bytes,
    int,
    str,
)
from collections.abc import (
    Iterable,
)
from google.protobuf.descriptor import (
    Descriptor,
    FileDescriptor,
)
from google.protobuf.internal.containers import (
    RepeatedScalarFieldContainer,
)
from google.protobuf.message import (
    Message,
)

DESCRIPTOR: FileDescriptor

@typing_extensions.final
class Empty(Message):
    """
    Generic protobuf messages
    """

    DESCRIPTOR: Descriptor

    def __init__(
        self,
    ) -> None: ...

@typing_extensions.final
class Request(Message):
    """Request - Common fields used in all gRPC requests"""

    DESCRIPTOR: Descriptor

    ASYNC_FIELD_NUMBER: int
    TIMEOUT_FIELD_NUMBER: int
    BEACONID_FIELD_NUMBER: int
    SESSIONID_FIELD_NUMBER: int
    Async: bool
    Timeout: int
    BeaconID: str
    SessionID: str
    def __init__(
        self,
        *,
        Async: bool = ...,
        Timeout: int = ...,
        BeaconID: str = ...,
        SessionID: str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["Async", b"Async", "BeaconID", b"BeaconID", "SessionID", b"SessionID", "Timeout", b"Timeout"]) -> None: ...

@typing_extensions.final
class Response(Message):
    """Response - Common fields used in all gRPC responses. Note that the Err field
               only used when the implant needs to return an error to the server.
               Client<->Server comms should use normal gRPC error handling.
    """

    DESCRIPTOR: Descriptor

    ERR_FIELD_NUMBER: int
    ASYNC_FIELD_NUMBER: int
    BEACONID_FIELD_NUMBER: int
    TASKID_FIELD_NUMBER: int
    Err: str
    Async: bool
    BeaconID: str
    TaskID: str
    def __init__(
        self,
        *,
        Err: str = ...,
        Async: bool = ...,
        BeaconID: str = ...,
        TaskID: str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["Async", b"Async", "BeaconID", b"BeaconID", "Err", b"Err", "TaskID", b"TaskID"]) -> None: ...

@typing_extensions.final
class File(Message):
    """File - A basic file data type"""

    DESCRIPTOR: Descriptor

    NAME_FIELD_NUMBER: int
    DATA_FIELD_NUMBER: int
    Name: str
    Data: bytes
    def __init__(
        self,
        *,
        Name: str = ...,
        Data: bytes = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["Data", b"Data", "Name", b"Name"]) -> None: ...

@typing_extensions.final
class Process(Message):
    """Process - A basic process data type"""

    DESCRIPTOR: Descriptor

    PID_FIELD_NUMBER: int
    PPID_FIELD_NUMBER: int
    EXECUTABLE_FIELD_NUMBER: int
    OWNER_FIELD_NUMBER: int
    ARCHITECTURE_FIELD_NUMBER: int
    SESSIONID_FIELD_NUMBER: int
    CMDLINE_FIELD_NUMBER: int
    Pid: int
    Ppid: int
    Executable: str
    Owner: str
    Architecture: str
    SessionID: int
    @property
    def CmdLine(self) -> RepeatedScalarFieldContainer[str]: ...
    def __init__(
        self,
        *,
        Pid: int = ...,
        Ppid: int = ...,
        Executable: str = ...,
        Owner: str = ...,
        Architecture: str = ...,
        SessionID: int = ...,
        CmdLine: Iterable[str] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["Architecture", b"Architecture", "CmdLine", b"CmdLine", "Executable", b"Executable", "Owner", b"Owner", "Pid", b"Pid", "Ppid", b"Ppid", "SessionID", b"SessionID"]) -> None: ...

@typing_extensions.final
class EnvVar(Message):
    """EnvVar - Environment variable K/V"""

    DESCRIPTOR: Descriptor

    KEY_FIELD_NUMBER: int
    VALUE_FIELD_NUMBER: int
    Key: str
    Value: str
    def __init__(
        self,
        *,
        Key: str = ...,
        Value: str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["Key", b"Key", "Value", b"Value"]) -> None: ...
