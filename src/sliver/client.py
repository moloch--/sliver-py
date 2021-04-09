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
from .pb.commonpb import common_pb2
from .pb.clientpb import client_pb2
from .pb.sliverpb import sliver_pb2
from .pb.rpcpb.services_pb2_grpc import SliverRPCServicer, SliverRPCStub
from .config import SliverClientConfig


KB = 1024
MB = 1024 * KB
GB = 1024 * MB
TIMEOUT = 60


class BaseClient(SliverRPCServicer):

    # 2GB triggers an overflow error in the gRPC library so we do 2GB-1
    MAX_MESSAGE_LENGTH = (2 * GB) - 1

    KEEP_ALIVE_TIMEOUT = 10000
    CERT_COMMON_NAME = 'multiplayer'

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
    
    @property
    def options(self):
        return [
            ('grpc.keepalive_timeout_ms', self.KEEP_ALIVE_TIMEOUT),
            ('grpc.ssl_target_name_override', self.CERT_COMMON_NAME),
            ('grpc.max_send_message_length', self.MAX_MESSAGE_LENGTH),
            ('grpc.max_receive_message_length', self.MAX_MESSAGE_LENGTH),
        ]

    def is_connected(self) -> bool:
        return self._channel is not None
    

class SliverAsyncClient(BaseClient):

    ''' Asyncio client implementation '''

    async def connect(self) -> None:
        self._channel = grpc.aio.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)

    async def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        return (await self._stub.GetVersion(common_pb2.Empty(), timeout=timeout))

    async def operators(self, timeout=TIMEOUT) -> list[client_pb2.Operator]:
        operators = await self._stub.GetOperators(common_pb2.Empty(), timeout=timeout)
        return list(operators.Operators)

    async def sessions(self, timeout=TIMEOUT) -> list[client_pb2.Session]:
        sessions: client_pb2.Sessions = await self._stub.GetSessions(common_pb2.Empty(), timeout=timeout)
        return list(sessions.Sessions)

    async def kill_session(self, session_id: int, force=False, timeout=TIMEOUT) -> None:
        kill = sliver_pb2.KillSessionReq()
        kill.Request.SessionID = session_id
        kill.Request.Timeout = timeout-1
        kill.Force = force
        await self._stub.KillSession(kill, timeout=timeout)

    async def jobs(self, timeout=TIMEOUT) -> list[client_pb2.Job]:
        jobs: client_pb2.Jobs = await self._stub.GetJobs(common_pb2.Empty(), timeout=timeout)
        return list(jobs.Jobs)

    async def kill_job(self, job_id: int, timeout=TIMEOUT) -> client_pb2.KillJob:
        kill = client_pb2.KillJobReq()
        kill.ID = job_id
        return (await self._stub.KillJob(kill, timeout=timeout))

    async def start_mtls_listener(self, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.MTLSListener:
        mtls = client_pb2.MTLSListenerReq()
        mtls.Host = host
        mtls.Port = port
        mtls.Persistent = persistent
        return (await self._stub.StartMTLSListener(mtls, timeout=timeout))

    async def start_wg_listener(self, port: int, tun_ip: str, n_port: int, key_port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.WGListener:
        wg = client_pb2.WGListenerReq()
        wg.Port = port
        wg.TunIP = tun_ip
        wg.NPort = n_port
        wg.KeyPort = key_port
        wg.Persistent = persistent
        return (await self._stub.StartWGListener(wg, timeout=timeout))

    async def start_dns_listener(self, domains: list[str], canaries: bool, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.DNSListener:
        dns = client_pb2.DNSListenerReq()
        dns.Domains = domains
        dns.Canaries = canaries
        dns.Host = host
        dns.Port = port
        dns.Persistent = persistent
        return (await self._stub.StartDNSListener(dns, timeout=timeout))

    async def start_https_listener(self, domain: str, host: str, port: int, secure: bool, website: str, cert: bytes, key: bytes, acme: bool, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = secure
        http.Website = website
        http.Cert = cert
        http.Key = key
        http.ACME = acme
        http.Persistent = persistent
        return (await self._stub.StartHTTPListener(http, timeout=timeout))

    async def start_http_listener(self, domain: str, host: str, port: int, secure: bool, website: str, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = False
        http.Website = website
        http.ACME = False
        http.Persistent = persistent
        return (await self._stub.StartHTTPListener(http, timeout=timeout))


class SliverClient(BaseClient):

    ''' Client implementation '''

    def connect(self) -> None:
        self._channel = grpc.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)
    
    def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        return self._stub.GetVersion(common_pb2.Empty(), timeout=timeout)

    def operators(self, timeout=TIMEOUT) -> list[client_pb2.Operator]:
        operators = self._stub.GetOperators(common_pb2.Empty(), timeout=timeout)
        return list(operators.Operators)

    def sessions(self, timeout=TIMEOUT) -> list[client_pb2.Session]:
        sessions: client_pb2.Sessions = self._stub.GetSessions(common_pb2.Empty(), timeout=timeout)
        return list(sessions.Sessions)

    def kill_session(self, session_id: int, force=False, timeout=TIMEOUT) -> None:
        kill = sliver_pb2.KillSessionReq()
        kill.Request.SessionID = session_id
        kill.Request.Timeout = timeout-1
        kill.Force = force
        self._stub.KillSession(kill, timeout=timeout)

    def jobs(self, timeout=TIMEOUT) -> list[client_pb2.Job]:
        jobs: client_pb2.Jobs = self._stub.GetJobs(common_pb2.Empty(), timeout=timeout)
        return list(jobs.Jobs)

    def kill_job(self, job_id: int, timeout=TIMEOUT) -> client_pb2.KillJob:
        kill = client_pb2.KillJobReq()
        kill.ID = job_id
        return self._stub.KillJob(kill, timeout=timeout)

    def start_mtls_listener(self, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.MTLSListener:
        mtls = client_pb2.MTLSListenerReq()
        mtls.Host = host
        mtls.Port = port
        mtls.Persistent = persistent
        return self._stub.StartMTLSListener(mtls, timeout=timeout)

    def start_wg_listener(self, port: int, tun_ip: str, n_port: int, key_port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.WGListener:
        wg = client_pb2.WGListenerReq()
        wg.Port = port
        wg.TunIP = tun_ip
        wg.NPort = n_port
        wg.KeyPort = key_port
        wg.Persistent = persistent
        return self._stub.StartWGListener(wg, timeout=timeout)

    def start_dns_listener(self, domains: list[str], canaries: bool, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.DNSListener:
        dns = client_pb2.DNSListenerReq()
        dns.Domains = domains
        dns.Canaries = canaries
        dns.Host = host
        dns.Port = port
        dns.Persistent = persistent
        return self._stub.StartDNSListener(dns, timeout=timeout)

    def start_https_listener(self, domain: str, host: str, port: int, secure: bool, website: str, cert: bytes, key: bytes, acme: bool, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = secure
        http.Website = website
        http.Cert = cert
        http.Key = key
        http.ACME = acme
        http.Persistent = persistent
        return self._stub.StartHTTPListener(http, timeout=timeout)

    def start_http_listener(self, domain: str, host: str, port: int, secure: bool, website: str, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = False
        http.Website = website
        http.ACME = False
        http.Persistent = persistent
        return self._stub.StartHTTPListener(http, timeout=timeout)

