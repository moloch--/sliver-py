"""
    Sliver Implant Framework
    Copyright (C) 2022  Bishop Fox

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import functools
import logging
from typing import Any, Dict, List, Tuple

import grpc

from ._protocols import PbWithRequestProp
from .interactive import BaseInteractiveCommands
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub
from .protobuf import client_pb2, common_pb2, sliver_pb2


class BaseBeacon:
    def __init__(
        self,
        beacon: client_pb2.Beacon,
        channel: grpc.aio.Channel,
        timeout: int = 60,
    ):
        """Base class for Beacon classes.

        :param beacon: Beacon protobuf object.
        :type beacon: client_pb2.Beacon
        :param channel: A gRPC channel.
        :type channel: grpc.aio.Channel
        :param timeout: Seconds to wait for timeout, defaults to TIMEOUT
        :type timeout: int, optional
        """
        self._log = logging.getLogger(self.__class__.__name__)
        self._channel = channel
        self._beacon = beacon
        self._stub = SliverRPCStub(channel)
        self.timeout = timeout
        self.beacon_tasks: Dict[str, Tuple[asyncio.Future, Any]] = {}
        asyncio.get_event_loop().create_task(self.taskresult_events())

    @property
    def beacon_id(self) -> str:
        """Beacon ID"""
        return self._beacon.ID

    @property
    def name(self) -> str:
        """Beacon name"""
        return self._beacon.Name

    @property
    def hostname(self) -> str:
        """Beacon hostname"""
        return self._beacon.Hostname

    @property
    def uuid(self) -> str:
        """Beacon UUID"""
        return self._beacon.UUID

    @property
    def username(self) -> str:
        """Username"""
        return self._beacon.Username

    @property
    def uid(self) -> str:
        """User ID"""
        return self._beacon.UID

    @property
    def gid(self) -> str:
        """Group ID"""
        return self._beacon.GID

    @property
    def os(self) -> str:
        """Operating system"""
        return self._beacon.OS

    @property
    def arch(self) -> str:
        """Architecture"""
        return self._beacon.Arch

    @property
    def transport(self) -> str:
        """Transport Method"""
        return self._beacon.Transport

    @property
    def remote_address(self) -> str:
        """Remote address"""
        return self._beacon.RemoteAddress

    @property
    def pid(self) -> int:
        """Process ID"""
        return self._beacon.PID

    @property
    def filename(self) -> str:
        """Beacon filename"""
        return self._beacon.Filename

    @property
    def last_checkin(self) -> int:
        """Last check in time"""
        return self._beacon.LastCheckin

    @property
    def active_c2(self) -> str:
        """Active C2"""
        return self._beacon.ActiveC2

    @property
    def version(self) -> str:
        """Version"""
        return self._beacon.Version

    @property
    def reconnect_interval(self) -> int:
        """Reconnect interval"""
        return self._beacon.ReconnectInterval

    def _request(self, pb: PbWithRequestProp):
        """
        Set request attributes based on current beacon, I'd prefer to return a generic Request
        object, but protobuf for whatever reason doesn't let you assign this type of field directly.

        `pb` in this case is any protobuf message with a .Request field.

        :param pb: A protobuf request object.
        """
        pb.Request.BeaconID = self._beacon.ID
        pb.Request.Timeout = self.timeout - 1
        pb.Request.Async = True
        return pb

    async def taskresult_events(self):
        """
        Monitor task events for results, resolve futures for any results
        we get back.
        """
        async for event in self._stub.Events(common_pb2.Empty()):
            if event.EventType != "beacon-taskresult":
                continue
            try:
                beacon_task = client_pb2.BeaconTask()
                beacon_task.ParseFromString(event.Data)
                if beacon_task.ID not in self.beacon_tasks:
                    continue
                task_content = await self._stub.GetBeaconTaskContent(
                    client_pb2.BeaconTask(ID=beacon_task.ID)
                )
                task_future, pb_object = self.beacon_tasks[beacon_task.ID]
                del self.beacon_tasks[beacon_task.ID]
                if pb_object is not None:
                    result = pb_object()
                    result.ParseFromString(task_content.Response)
                else:
                    result = None
                task_future.set_result(result)
            except Exception as err:
                self._log.exception(err)


def beacon_taskresult(pb_object: Any):
    """
    Wraps a class method to return a future that resolves when the
    beacon task result is available.
    """

    def func(method):
        @functools.wraps(method)
        async def wrapper(self, *args, **kwargs):
            task_response = await method(self, *args, **kwargs)
            self.beacon_tasks[task_response.Response.TaskID] = (
                asyncio.Future(),
                pb_object,
            )
            return self.beacon_tasks[task_response.Response.TaskID][0]

        return wrapper

    return func


class InteractiveBeacon(BaseBeacon, BaseInteractiveCommands):

    """Wrap all commands that can be executed against a beacon mode implant"""

    async def interactive_session(self):
        pass

    # ----------------  Wrapped super() commands ----------------

    @beacon_taskresult(sliver_pb2.Ping)
    async def ping(self, *args, **kwargs) -> sliver_pb2.Ping:
        return await super().ping(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Ps)
    async def ps(self, *args, **kwargs) -> List[common_pb2.Process]:
        return await super().ps(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Terminate)
    async def terminate(self, *args, **kwargs) -> sliver_pb2.Terminate:
        return await super().terminate(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Ifconfig)
    async def ifconfig(self, *args, **kwargs) -> sliver_pb2.Ifconfig:
        return await super().ifconfig(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Netstat)
    async def netstat(self, *args, **kwargs) -> sliver_pb2.Netstat:
        return await super().netstat(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Ls)
    async def ls(self, *args, **kwargs) -> sliver_pb2.Ls:
        return await super().ls(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Pwd)
    async def cd(self, *args, **kwargs) -> sliver_pb2.Pwd:
        return await super().cd(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Pwd)
    async def pwd(self, *args, **kwargs) -> sliver_pb2.Pwd:
        return await super().pwd(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Rm)
    async def rm(self, *args, **kwargs) -> sliver_pb2.Rm:
        return await super().rm(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Mkdir)
    async def mkdir(self, *args, **kwargs) -> sliver_pb2.Mkdir:
        return await super().mkdir(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Download)
    async def download(self, *args, **kwargs) -> sliver_pb2.Download:
        return await super().download(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Upload)
    async def upload(self, *args, **kwargs) -> sliver_pb2.Upload:
        return await super().upload(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.ProcessDump)
    async def process_dump(self, *args, **kwargs) -> sliver_pb2.ProcessDump:
        return await super().process_dump(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.RunAs)
    async def run_as(self, *args, **kwargs) -> sliver_pb2.RunAs:
        return await super().run_as(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Impersonate)
    async def impersonate(self, *args, **kwargs) -> sliver_pb2.Impersonate:
        return await super().impersonate(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.RevToSelf)
    async def revert_to_self(self, *args, **kwargs) -> sliver_pb2.RevToSelf:
        return await super().revert_to_self(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.GetSystem)
    async def get_system(self, *args, **kwargs) -> sliver_pb2.GetSystem:
        return await super().get_system(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Task)
    async def execute_shellcode(self, *args, **kwargs) -> sliver_pb2.Task:
        return await super().execute_shellcode(*args, **kwargs)

    @beacon_taskresult(None)
    async def msf(self, *args, **kwargs) -> None:
        return await super().msf(*args, **kwargs)

    @beacon_taskresult(None)
    async def msf_remote(self, *args, **kwargs) -> None:
        return await super().msf_remote(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.ExecuteAssembly)
    async def execute_assembly(self, *args, **kwargs) -> sliver_pb2.ExecuteAssembly:
        return await super().execute_assembly(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Migrate)
    async def migrate(self, *args, **kwargs) -> sliver_pb2.Migrate:
        return await super().migrate(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Execute)
    async def execute(self, *args, **kwargs) -> sliver_pb2.Execute:
        return await super().execute(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Sideload)
    async def sideload(self, *args, **kwargs) -> sliver_pb2.Sideload:
        return await super().sideload(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.SpawnDll)
    async def spawn_dll(self, *args, **kwargs) -> sliver_pb2.SpawnDll:
        return await super().spawn_dll(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.Screenshot)
    async def screenshot(self, *args, **kwargs) -> sliver_pb2.Screenshot:
        return await super().screenshot(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.MakeToken)
    async def make_token(self, *args, **kwargs) -> sliver_pb2.MakeToken:
        return await super().make_token(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.EnvInfo)
    async def get_env(self, *args, **kwargs) -> sliver_pb2.EnvInfo:
        return await super().get_env(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.SetEnv)
    async def set_env(self, *args, **kwargs) -> sliver_pb2.SetEnv:
        return await super().set_env(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.RegistryRead)
    async def registry_read(self, *args, **kwargs) -> sliver_pb2.RegistryRead:
        return await super().registry_read(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.RegistryWrite)
    async def registry_write(self, *args, **kwargs) -> sliver_pb2.RegistryWrite:
        return await super().registry_write(*args, **kwargs)

    @beacon_taskresult(sliver_pb2.RegistryCreateKey)
    async def registry_create_key(
        self, *args, **kwargs
    ) -> sliver_pb2.RegistryCreateKey:
        return await super().registry_create_key(*args, **kwargs)
