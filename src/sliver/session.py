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

import grpc
import logging
from typing import Union, List

from .interactive import BaseInteractiveCommands
from .protobuf import client_pb2
from .protobuf import sliver_pb2
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub


TIMEOUT = 60


class BaseSession(object):

    def __init__(self, session: client_pb2.Session, channel: grpc.Channel, timeout: int = TIMEOUT, logger: Union[logging.Handler, None] = None):
        self._channel = channel
        self._session = session
        self._stub = SliverRPCStub(channel)
        self.timeout = timeout

    def _request(self, pb):
        '''
        Set request attributes based on current session, I'd prefer to return a generic Request
        object, but protobuf for whatever reason doesn't let you assign this type of field directly.

        `pb` in this case is any protobuf message with a .Request field.

        :param pb: A protobuf request object.
        '''
        pb.Request.SessionID = self._session.ID
        pb.Request.Timeout = self.timeout-1
        return pb

    @property
    def session_id(self) -> int:
        return self._session.ID
    
    @property
    def name(self) -> str:
        return self._session.Name
    
    @property
    def hostname(self) -> int:
        return self._session.Hostname
    
    @property
    def uuid(self) -> str:
        return self._session.UUID
    
    @property
    def username(self) -> str:
        return self._session.Username
    
    @property
    def uid(self) -> str:
        return self._session.UID

    @property
    def gid(self) -> str:
        return self._session.GID

    @property
    def os(self) -> str:
        return self._session.OS

    @property
    def arch(self) -> str:
        return self._session.Arch

    @property
    def transport(self) -> str:
        return self._session.Transport

    @property
    def remote_address(self) -> str:
        return self._session.RemoteAddress

    @property
    def pid(self) -> int:
        return self._session.PID

    @property
    def filename(self) -> str:
        return self._session.Filename

    @property
    def last_checkin(self) -> str:
        return self._session.LastCheckin

    @property
    def active_c2(self) -> str:
        return self._session.ActiveC2

    @property
    def version(self) -> str:
        return self._session.Version

    @property
    def is_dead(self) -> bool:
        return self._session.IsDead

    @property
    def reconnect_interval(self) -> int:
        return self._session.ReconnectInterval

    @property
    def proxy_url(self) -> str:
        return self._session.ProxyURL


class InteractiveSession(BaseSession, BaseInteractiveCommands):

    '''
    Session-only commands, session/beacon commands are defined in the 
    BaseAsyncInteractiveCommands class.
    '''

    async def pivot_listeners(self) -> List[sliver_pb2.PivotListener]:
        '''List C2 pivots

        :return: [description]
        :rtype: List[sliver_pb2.PivotListener]
        '''        
        pivots = await self._stub.ListPivots(self._request(sliver_pb2.PivotListenersReq()), timeout=self.timeout)
        return list(pivots.Listeners)

    async def start_service(self, name: str, description: str, exe: str, hostname: str, arguments: str) -> sliver_pb2.ServiceInfo:
        '''Create and start a Windows service (Windows only)

        :param name: Name of the service
        :type name: str
        :param description: Service description
        :type description: str
        :param exe: Path to the service .exe file
        :type exe: str
        :param hostname: Hostname
        :type hostname: str
        :param arguments: Arguments to start the service with
        :type arguments: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        '''        
        svc = sliver_pb2.StartServiceReq()
        svc.ServiceName = name
        svc.ServiceDescription = description
        svc.BinPath = exe
        svc.Hostname = hostname
        svc.Arguments = arguments
        return (await self._stub.StartService(self._request(svc), timeout=self.timeout))
    
    async def stop_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        '''Stop a Windows service (Windows only)

        :param name: Name of the servie
        :type name: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        '''        
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return (await self._stub.StopService(self._request(svc), timeout=self.timeout))

    async def remove_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        '''Remove a Windows service (Windows only)

        :param name: Name of the service
        :type name: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf ServiceInfo object
        :rtype: sliver_pb2.ServiceInfo
        '''        
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return (await self._stub.RemoveService(self._request(svc), timeout=self.timeout))

    async def backdoor(self, remote_path: str, profile_name: str) -> sliver_pb2.Backdoor:
        '''Backdoor a remote binary by injecting a Sliver payload into the executable using a code cave

        :param remote_path: Remote path to an executable to backdoor
        :type remote_path: str
        :param profile_name: Implant profile name to inject into the binary
        :type profile_name: str
        :return: Protobuf Backdoor object
        :rtype: sliver_pb2.Backdoor
        '''        
        backdoor = sliver_pb2.BackdoorReq()
        backdoor.FilePath = remote_path
        backdoor.ProfileName = profile_name
        return (await self._stub.Backdoor(self._request(backdoor), timeout=self.timeout))
    