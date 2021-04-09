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
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub
from .config import SliverClientConfig


KB = 1024
MB = 1024 * KB
GB = 1024 * MB
TIMEOUT = 60


class BaseClient(object):

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


    async def update_session(self, session_id: int, name: str, timeout=TIMEOUT) -> client_pb2.Session:
        update = client_pb2.UpdateSession()
        update.SessionID = session_id
        update.Name = name
        return (await self._stub.UpdateSession(update, timeout=timeout))

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

    async def start_tcp_stager_listener(self, protocol: client_pb2.StageProtocol, host: str, port: int, data: bytes, timeout=TIMEOUT) -> client_pb2.StagerListener:
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = protocol
        stage.Host = host
        stage.Port = port
        stage.Data = data
        return (await self._stub.StartTCPStagerListener(stage, timeout=timeout))

    async def start_http_stager_listener(self, protocol: client_pb2.StageProtocol, host: str, port: int, data: bytes, cert: bytes, key: bytes, acme: bool, timeout=TIMEOUT) -> client_pb2.StagerListener:
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = protocol
        stage.Host = host
        stage.Port = port
        stage.Data = data
        stage.Cert = cert
        stage.Key = key
        stage.ACME = acme
        return (await self._stub.StartHTTPStagerListener(stage, timeout=timeout))

    async def generate(self, config: client_pb2.ImplantConfig, timeout=360) -> client_pb2.Generate:
        req = client_pb2.GenerateReq()
        req.ImplantConfig = config
        return (await self._stub.Generate(req, timeout=timeout))

    async def regenerate(self, implant_name: str, timeout=TIMEOUT) -> client_pb2.Generate:
        regenerate = client_pb2.RegenerateReq()
        regenerate.ImpantName = implant_name
        return (await self._stub.Regenerate(regenerate, timeout=timeout))

    async def implant_builds(self, implant_name: str, timeout=TIMEOUT) -> None:
        delete = client_pb2.DeleteReq()
        delete.Name = implant_name
        await self._stub.DeleteImplantBuild(delete, timeout=timeout)
    
    async def canaries(self, timeout=TIMEOUT) -> list[client_pb2.DNSCanary]:
        canaries = await self._stub.Canaries(common_pb2.Empty(), timeout=timeout)
        return list(canaries.Canaries)
    
    async def generate_wg_client_config(self, timeout=TIMEOUT) -> client_pb2.WGClientConfig:
        return (await self._stub.GenerateWGClientConfig(common_pb2.Empty(), timeout=timeout))

    async def generate_unique_ip(self, timeout=TIMEOUT) -> client_pb2.UniqueWGIP:
        return (await self._stub.GenerateUniqueIP(common_pb2.Empty(), timeout=timeout))
    
    async def implant_profiles(self, timeout=TIMEOUT) -> list[client_pb2.ImplantProfile]:
        profiles = await self._stub.ImplantProfiles(common_pb2.Empty(), timeout=timeout)
        return list(profiles.Profiles)
    
    async def delete_implant_profile(self, profile_name, timeout=TIMEOUT) -> None:
        delete = client_pb2.DeleteReq()
        delete.Name = profile_name
        await self._stub.DeleteImplantProfile(delete, timeout=timeout)
    
    async def save_implant_profile(self, profile: client_pb2.ImplantProfile, timeout=TIMEOUT) -> client_pb2.ImplantProfile:
        return (await self._stub.SaveImplantProfile(profile, timeout=timeout))
    
    async def msf_stage(self, arch: str, format: str, host: str, port: int, os: str, protocol: client_pb2.StageProtocol, badchars=[], timeout=TIMEOUT) -> client_pb2.MsfStager:
        stagerReq = client_pb2.MsfStagerReq()
        stagerReq.Arch = arch
        stagerReq.Format = format
        stagerReq.Port = port
        stagerReq.Host = host
        stagerReq.OS = os
        stagerReq.Protocol = protocol
        stagerReq.BadChars = badchars
        return (await self._stub.MsfStage(stagerReq, timeout=timeout))

    async def shellcode_rdi(self, data: bytes, function_name: str, arguments: str, timeout=TIMEOUT) -> client_pb2.ShellcodeRDI:
        shellReq = client_pb2.ShellcodeRDIReq()
        shellReq.Data = data
        shellReq.FunctionName = function_name
        shellReq.Arguments = arguments
        return (await self._stub.ShellcodeRDI(shellReq, timeout=timeout))


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

    def update_session(self, session_id: int, name: str, timeout=TIMEOUT) -> client_pb2.Session:
        update = client_pb2.UpdateSession()
        update.SessionID = session_id
        update.Name = name
        return self._stub.UpdateSession(update, timeout=timeout)

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

    def start_tcp_stager_listener(self, protocol: client_pb2.StageProtocol, host: str, port: int, data: bytes, timeout=TIMEOUT) -> client_pb2.StagerListener:
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = protocol
        stage.Host = host
        stage.Port = port
        stage.Data = data
        return self._stub.StartTCPStagerListener(stage, timeout=timeout)

    def start_http_stager_listener(self, protocol: client_pb2.StageProtocol, host: str, port: int, data: bytes, cert: bytes, key: bytes, acme: bool, timeout=TIMEOUT) -> client_pb2.StagerListener:
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = protocol
        stage.Host = host
        stage.Port = port
        stage.Data = data
        stage.Cert = cert
        stage.Key = key
        stage.ACME = acme
        return self._stub.StartHTTPStagerListener(stage, timeout=timeout)

    def generate(self, config: client_pb2.ImplantConfig, timeout=360) -> client_pb2.Generate:
        req = client_pb2.GenerateReq()
        req.ImplantConfig = config
        return self._stub.Generate(req, timeout=timeout)

    def regenerate(self, implant_name: str, timeout=TIMEOUT) -> client_pb2.Generate:
        regenerate = client_pb2.RegenerateReq()
        regenerate.ImpantName = implant_name
        return self._stub.Regenerate(regenerate, timeout=timeout)

    def implant_builds(self, implant_name: str, timeout=TIMEOUT) -> None:
        delete = client_pb2.DeleteReq()
        delete.Name = implant_name
        self._stub.DeleteImplantBuild(delete, timeout=timeout)
    
    def canaries(self, timeout=TIMEOUT) -> list[client_pb2.DNSCanary]:
        canaries = self._stub.Canaries(common_pb2.Empty(), timeout=timeout)
        return list(canaries.Canaries)
    
    def generate_wg_client_config(self, timeout=TIMEOUT) -> client_pb2.WGClientConfig:
        return self._stub.GenerateWGClientConfig(common_pb2.Empty(), timeout=timeout)

    def generate_unique_ip(self, timeout=TIMEOUT) -> client_pb2.UniqueWGIP:
        return self._stub.GenerateUniqueIP(common_pb2.Empty(), timeout=timeout)
    
    def implant_profiles(self, timeout=TIMEOUT) -> list[client_pb2.ImplantProfile]:
        profiles = self._stub.ImplantProfiles(common_pb2.Empty(), timeout=timeout)
        return list(profiles.Profiles)
    
    def delete_implant_profile(self, profile_name, timeout=TIMEOUT) -> None:
        delete = client_pb2.DeleteReq()
        delete.Name = profile_name
        self._stub.DeleteImplantProfile(delete, timeout=timeout)
    
    def save_implant_profile(self, profile: client_pb2.ImplantProfile, timeout=TIMEOUT) -> client_pb2.ImplantProfile:
        return self._stub.SaveImplantProfile(profile, timeout=timeout)
    
    def msf_stage(self, arch: str, format: str, host: str, port: int, os: str, protocol: client_pb2.StageProtocol, badchars=[], timeout=TIMEOUT) -> client_pb2.MsfStager:
        stagerReq = client_pb2.MsfStagerReq()
        stagerReq.Arch = arch
        stagerReq.Format = format
        stagerReq.Port = port
        stagerReq.Host = host
        stagerReq.OS = os
        stagerReq.Protocol = protocol
        stagerReq.BadChars = badchars
        return self._stub.MsfStage(stagerReq, timeout=timeout)

    def shellcode_rdi(self, data: bytes, function_name: str, arguments: str, timeout=TIMEOUT) -> client_pb2.ShellcodeRDI:
        shellReq = client_pb2.ShellcodeRDIReq()
        shellReq.Data = data
        shellReq.FunctionName = function_name
        shellReq.Arguments = arguments
        return self._stub.ShellcodeRDI(shellReq, timeout=timeout)
