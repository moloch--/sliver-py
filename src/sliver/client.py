"""
Sliver Implant Framework
Copyright (C) 2021  Bishop Fox
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


import grpc

from .pb.clientpb import client_pb2
from .pb.rpcpb.services_pb2_grpc import SliverRPCServicer, SliverRPCStub
from .config import SliverClientConfig


class BaseClient(SliverRPCServicer):

    def __init__(self, config: SliverClientConfig):
        self.config = config
        self._channel: grpc.Channel = None
        self._stub: SliverRPCStub = None

    @property
    def target(self) -> str:
        return "%s:%d" % (self.config.lhost, self.config.lport,)

    @property
    def credentials(self) -> grpc.ChannelCredentials:
        return grpc.ssl_channel_credentials(
            root_certificates=self.config.ca_certificate.encode(),
            private_key=self.config.private_key.encode(),
            certificate_chain=self.config.certificate.encode(),
        )

    def is_connected(self) -> bool:
        return self._channel is not None


class SliverAsyncClient(BaseClient):

    ''' Asyncio client implementation '''

    async def connect(self) -> None:
        self._channel = await grpc.aio.secure_channel(self.target, self.credentials)
        self._stub = SliverRPCStub(self._channel)


class SliverClient(BaseClient):

    ''' Client implementation '''

    def connect(self) -> None:
        self._channel = grpc.secure_channel(self.target, self.credentials)
        self._stub = SliverRPCStub(self._channel)

    def sessions(self) -> client_pb2.Session:
        sessions: client_pb2.Sessions = self._stub.GetSessions()
        return sessions

