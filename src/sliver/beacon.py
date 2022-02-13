'''
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
'''

import asyncio
import grpc
import logging
from typing import Generator, Union, List, Dict, Callable, Iterator

from .interactive import BaseAsyncInteractiveCommands
from .protobuf import common_pb2
from .protobuf import client_pb2
from .protobuf import sliver_pb2
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub


TIMEOUT = 60


class BaseBeacon(object):

    _beacon: client_pb2.Beacon
    beacon_tasks = {}

    def __init__(self, beacon: client_pb2.Beacon, channel: grpc.Channel, timeout: int = TIMEOUT, logger: Union[logging.Handler, None] = None):
        self._channel = channel
        self._beacon = beacon
        self._stub = SliverRPCStub(channel)
        self.timeout = timeout
        asyncio.get_event_loop().create_task(self.taskresult_events())

    def _request(self, pb):
        '''
        Set request attributes based on current beacon, I'd prefer to return a generic Request
        object, but protobuf for whatever reason doesn't let you assign this type of field directly.

        `pb` in this case is any protobuf message with a .Request field.

        :param pb: A protobuf request object.
        '''
        pb.Request.SessionID = self._beacon.ID
        pb.Request.Timeout = self.timeout-1
        pb.Request.Async = True
        return pb

    async def taskresult_events(self) -> Generator[client_pb2.Event, None, None]:
        '''
        Monitor task events for results, resolve futures for any results
        we get back.
        '''        
        async for event in self._stub.Events(common_pb2.Empty()):
            if event.EventType != "beacon-taskresult":
                continue
            beacon_task = client_pb2.BeaconTask()
            beacon_task.ParseFromString(event.Data)
            if beacon_task.ID not in self.beacon_tasks:
                continue
            task_content = await self._stub.GetBeaconTaskContent(client_pb2.BeaconTask(ID=beacon_task.ID))
            self.beacon_tasks[beacon_task.ID].set_result(task_content)
            del self.beacon_tasks[beacon_task.ID]

    @property
    def beacon_id(self) -> int:
        return self._beacon.ID
    
    @property
    def name(self) -> str:
        return self._beacon.Name
    
    @property
    def hostname(self) -> int:
        return self._beacon.Hostname
    
    @property
    def uuid(self) -> str:
        return self._beacon.UUID
    
    @property
    def username(self) -> str:
        return self._beacon.Username
    
    @property
    def uid(self) -> str:
        return self._beacon.UID

    @property
    def gid(self) -> str:
        return self._beacon.GID

    @property
    def os(self) -> str:
        return self._beacon.OS

    @property
    def arch(self) -> str:
        return self._beacon.Arch

    @property
    def transport(self) -> str:
        return self._beacon.Transport

    @property
    def remote_address(self) -> str:
        return self._beacon.RemoteAddress

    @property
    def pid(self) -> int:
        return self._beacon.PID

    @property
    def filename(self) -> str:
        return self._beacon.Filename

    @property
    def last_checkin(self) -> str:
        return self._beacon.LastCheckin

    @property
    def active_c2(self) -> str:
        return self._beacon.ActiveC2

    @property
    def version(self) -> str:
        return self._beacon.Version

    @property
    def reconnect_interval(self) -> int:
        return self._beacon.ReconnectInterval

    
class AsyncInteractiveBeacon(BaseBeacon, BaseAsyncInteractiveCommands):

    async def ls(self, *args, **kwargs) -> sliver_pb2.Ls:
        task_response = await super().ls(*args, **kwargs)
        self.beacon_tasks[task_response.Response.TaskID] = asyncio.Future()
        return self.beacon_tasks[task_response.Response.TaskID]

