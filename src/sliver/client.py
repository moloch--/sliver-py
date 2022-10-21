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


import logging
from typing import AsyncGenerator, Dict, Iterable, List, Optional, Union

import grpc

from sliver.pb.commonpb.common_pb2 import Request

from .beacon import InteractiveBeacon
from .config import SliverClientConfig
from .pb.rpcpb.services_pb2_grpc import SliverRPCStub
from .protobuf import client_pb2, common_pb2, sliver_pb2
from .session import InteractiveSession

KB = 1024
MB = 1024 * KB
GB = 1024 * MB
TIMEOUT = 60


class BaseClient(object):

    # 2GB triggers an overflow error in the gRPC library so we do 2GB-1
    MAX_MESSAGE_LENGTH = (2 * GB) - 1

    KEEP_ALIVE_TIMEOUT = 10000
    CERT_COMMON_NAME = "multiplayer"

    def __init__(self, config: SliverClientConfig):
        self.config = config
        self._channel: grpc.aio.Channel
        self._stub: SliverRPCStub
        self._log = logging.getLogger(self.__class__.__name__)

    def is_connected(self) -> bool:
        return self._channel is not None

    @property
    def target(self) -> str:
        return "%s:%d" % (
            self.config.lhost,
            self.config.lport,
        )

    @property
    def credentials(self) -> grpc.ChannelCredentials:
        return grpc.composite_channel_credentials(
            grpc.ssl_channel_credentials(
                root_certificates=self.config.ca_certificate.encode(),
                private_key=self.config.private_key.encode(),
                certificate_chain=self.config.certificate.encode(),
            ),
            grpc.access_token_call_credentials(
                access_token=self.config.token,
            ),
        )

    @property
    def options(self):
        return [
            ("grpc.keepalive_timeout_ms", self.KEEP_ALIVE_TIMEOUT),
            ("grpc.ssl_target_name_override", self.CERT_COMMON_NAME),
            ("grpc.max_send_message_length", self.MAX_MESSAGE_LENGTH),
            ("grpc.max_receive_message_length", self.MAX_MESSAGE_LENGTH),
        ]


class SliverClient(BaseClient):

    """Asyncio client implementation"""

    beacon_event_types = ["beacon-registered"]
    session_event_types = ["session-connected", "session-disconnected"]
    job_event_types = ["job-started", "job-stopped"]
    canary_event_types = ["canary"]

    async def connect(self) -> client_pb2.Version:
        """Establish a connection to the Sliver server

        :return: Protobuf Version object, containing the server's version information
        :rtype: client_pb2.Version
        """
        self._channel = grpc.aio.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)
        return await self.version()

    async def interact_session(
        self, session_id: str, timeout=TIMEOUT
    ) -> Optional[InteractiveSession]:
        """Interact with a session, returns an :class:`InteractiveSession`

        :param session_id: Session ID
        :type session_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: An interactive session
        :rtype: Optional[InteractiveSession]
        """
        session = await self.session_by_id(session_id, timeout)
        if session:
            return InteractiveSession(session, self._channel, timeout)

    async def interact_beacon(
        self, beacon_id: str, timeout=TIMEOUT
    ) -> Optional[InteractiveBeacon]:
        """Interact with a beacon, returns an :class:`InteractiveBeacon`

        :param beacon_id: Beacon ID
        :type beacon_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: An interactive beacon
        :rtype: Optional[AsyncInteractiveBeacon]
        """
        beacon = await self.beacon_by_id(beacon_id, timeout)
        if beacon:
            return InteractiveBeacon(beacon, self._channel, timeout)

    async def session_by_id(
        self, session_id: str, timeout=TIMEOUT
    ) -> Optional[client_pb2.Session]:
        """Get the session information from a session ID

        :param session_id: Session ID
        :type session_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: Protobuf Session object
        :rtype: Optional[client_pb2.Session]
        """
        sessions = await self.sessions(timeout)
        for session in sessions:
            if session.ID == session_id:
                return session

    async def beacon_by_id(
        self, beacon_id: str, timeout=TIMEOUT
    ) -> Optional[client_pb2.Beacon]:
        """Get the beacon information from a beacon ID

        :param beacon_id: Beacon ID
        :type beacon_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: Protobuf Beacon object
        :rtype: Union[client_pb2.Beacon, None]
        """
        beacons = await self.beacons(timeout)
        for beacon in beacons:
            if beacon.ID == beacon_id:
                return beacon

    async def events(self) -> AsyncGenerator[client_pb2.Event, None]:
        """All events

        :yield: A stream of events
        :rtype: client_pb2.Event
        """
        async for event in self._stub.Events(common_pb2.Empty()):
            yield event

    async def on(
        self, event_types: Union[str, List[str]]
    ) -> AsyncGenerator[client_pb2.Event, None]:
        """Iterate on a specific event or list of events

        :param event_types: An event type or list of event types
        :type event_types: Union[str, List[str]]
        :yield: A stream of events of the given type(s)
        :rtype: client_pb2.Event
        """
        if isinstance(event_types, str):
            event_types = [event_types]
        async for event in self.events():
            if event.EventType in event_types:
                yield event

    async def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        """Get server version information

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Version object
        :rtype: client_pb2.Version
        """
        return await self._stub.GetVersion(common_pb2.Empty(), timeout=timeout)

    async def operators(self, timeout=TIMEOUT) -> List[client_pb2.Operator]:
        """Get a list of operators and their online status

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Operator objects
        :rtype: List[client_pb2.Operator]
        """
        operators = await self._stub.GetOperators(common_pb2.Empty(), timeout=timeout)
        return list(operators.Operators)

    async def sessions(self, timeout=TIMEOUT) -> List[client_pb2.Session]:
        """Get a list of active sessions

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Session objects
        :rtype: List[client_pb2.Session]
        """
        sessions: client_pb2.Sessions = await self._stub.GetSessions(
            common_pb2.Empty(), timeout=timeout
        )
        return list(sessions.Sessions)

    async def rename_session(self, session_id: str, name: str, timeout=TIMEOUT) -> None:
        """Rename a session

        :param session_id: Session ID to update
        :type session_id: str
        :param name: Rename session to this value
        :type name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: None
        :rtype: None
        """
        rename_req = client_pb2.RenameReq(SessionID=session_id, Name=name)
        await self._stub.Rename(rename_req, timeout=timeout)

    async def kill_session(self, session_id: str, force=False, timeout=TIMEOUT) -> None:
        """Kill a session

        :param session_id: Session ID to kill
        :type session_id: str
        :param force: Force kill the session, defaults to False
        :type force: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        request = Request(SessionID=session_id, Timeout=timeout)
        kill_req = sliver_pb2.KillReq(Force=force, Request=request)
        await self._stub.Kill(kill_req, timeout=timeout)

    async def beacons(self, timeout=TIMEOUT) -> List[client_pb2.Beacon]:
        """Get a list of active beacons

        :param timeout: gRPC timeout, defaults to 60 seconds
        :rtype: List[client_pb2.Beacon]
        """
        beacons: client_pb2.Beacons = await self._stub.GetBeacons(
            common_pb2.Empty(), timeout=timeout
        )
        return list(beacons.Beacons)

    async def rename_beacon(self, beacon_id: str, name: str, timeout=TIMEOUT) -> None:
        """Rename a beacon

        :param beacon_id: Beacon ID to update
        :type beacon_id: str
        :param name: Rename beacon to this value
        :type name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: None
        :rtype: None
        """
        rename_req = client_pb2.RenameReq(BeaconID=beacon_id, Name=name)
        await self._stub.Rename(rename_req, timeout=timeout)

    async def kill_beacon(self, beacon_id: str, timeout=TIMEOUT) -> None:
        """Kill a beacon

        :param beacon_id: Numeric beacon ID to remove
        :type beacon_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        beacon_rm = client_pb2.Beacon(ID=beacon_id)
        await self._stub.RmBeacon(beacon_rm, timeout=timeout)

    async def beacon_tasks(
        self, beacon_id: str, timeout=TIMEOUT
    ) -> List[client_pb2.BeaconTask]:
        """Get a list of tasks for a beacon

        :param beacon_id: Beacon ID to get tasks for
        :type beacon_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Task objects
        :rtype: List[client_pb2.Task]
        """
        beacon = client_pb2.Beacon(ID=beacon_id)
        tasks = await self._stub.GetBeaconTasks(beacon, timeout=timeout)
        return list(tasks.Tasks)

    async def beacon_task_content(
        self, task_id: str, timeout=TIMEOUT
    ) -> List[client_pb2.BeaconTask]:
        """Get a list of tasks for a beacon

        :param task_id: Task ID get contents for
        :type task_id: sts
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Task objects
        :rtype: List[client_pb2.Task]
        """
        beacon = client_pb2.Beacon(ID=task_id)
        task = await self._stub.GetBeaconTaskContent(beacon, timeout=timeout)
        return task

    async def jobs(self, timeout=TIMEOUT) -> List[client_pb2.Job]:
        """Get a list of active jobs

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Job objects
        :rtype: List[client_pb2.Job]
        """
        jobs: client_pb2.Jobs = await self._stub.GetJobs(
            common_pb2.Empty(), timeout=timeout
        )
        return list(jobs.Active)

    async def job_by_id(self, job_id: int, timeout=TIMEOUT) -> Optional[client_pb2.Job]:
        """Get job by id

        :param job_id: Beacon ID to get tasks for
        :type job_id: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Job objects
        :rtype: List[client_pb2.Job]
        """
        for job in await self.jobs(timeout=timeout):
            if job.ID == job_id:
                return job

    async def job_by_port(
        self, job_port: int, timeout=TIMEOUT
    ) -> Optional[client_pb2.Job]:
        """Get job by port

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Job objects
        :rtype: List[client_pb2.Job]
        """
        for job in await self.jobs(timeout=timeout):
            if job.Port == job_port:
                return job

    async def kill_job(self, job_id: int, timeout=TIMEOUT) -> client_pb2.KillJob:
        """Kill a job

        :param job_id: Numeric job ID to kill
        :type job_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf KillJob object
        :rtype: client_pb2.KillJob
        """
        kill_req = client_pb2.KillJobReq(ID=job_id)
        return await self._stub.KillJob(kill_req, timeout=timeout)

    async def start_mtls_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        persistent: bool = False,
        timeout=TIMEOUT,
    ) -> client_pb2.MTLSListener:
        """Start a mutual TLS (mTLS) C2 listener

        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf MTLSListener object
        :rtype: client_pb2.MTLSListener
        """
        mtls_req = client_pb2.MTLSListenerReq(
            Host=host, Port=port, Persistent=persistent
        )
        return await self._stub.StartMTLSListener(mtls_req, timeout=timeout)

    async def start_wg_listener(
        self,
        tun_ip: str,
        port: int = 53,
        n_port: int = 8888,
        key_port: int = 1337,
        persistent: bool = False,
        timeout: int = TIMEOUT,
    ) -> client_pb2.WGListener:
        """Start a WireGuard (wg) C2 listener

        :param tun_ip: Virtual TUN IP listen address
        :type tun_ip: str
        :param port: UDP port to start listener on
        :type port: int
        :param n_port: Virtual TUN port number
        :type n_port: int
        :param key_port: Virtual TUN port number for key exchanges
        :type key_port: int
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf WGListener object
        :rtype: client_pb2.WGListener
        """
        wg_req = client_pb2.WGListenerReq(
            TunIP=tun_ip,
            Port=port,
            NPort=n_port,
            KeyPort=key_port,
            Persistent=persistent,
        )
        return await self._stub.StartWGListener(wg_req, timeout=timeout)

    async def start_dns_listener(
        self,
        domains: List[str],
        host: str = "0.0.0.0",
        port: int = 53,
        canaries: bool = True,
        persistent: bool = False,
        enforce_otp=True,
        timeout: int = TIMEOUT,
    ) -> client_pb2.DNSListener:
        """Start a DNS C2 listener

        :param domains: C2 domains to listen for
        :type domains: List[str]
        :param canaries: Enable/disable DNS canaries
        :type canaries: bool
        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param enforce_otp: Enforce OTP auth for DNS C2, defaults to True
        :type enforce_otp: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf DNSListener object
        :rtype: client_pb2.DNSListener
        """
        # Ensure domains always have a trailing dot
        domains = list(map(lambda d: d + "." if d[-1] != "." else d, domains))

        dns_req = client_pb2.DNSListenerReq(
            Domains=domains,
            Canaries=canaries,
            Host=host,
            Port=port,
            Persistent=persistent,
            EnforceOTP=enforce_otp,
        )
        return await self._stub.StartDNSListener(dns_req, timeout=timeout)

    async def start_http_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 80,
        website: str = "",
        domain: str = "",
        persistent: bool = False,
        timeout: int = TIMEOUT,
    ) -> client_pb2.HTTPListener:
        """Start an HTTP C2 listener


        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param website: Name of the "website" to host on listener
        :type website: str
        :param domain: Domain name for HTTP server (one domain per listener)
        :type domain: str
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        """
        http_req = client_pb2.HTTPListenerReq(
            Domain=domain,
            Host=host,
            Port=port,
            Secure=False,
            Website=website,
            Persistent=persistent,
        )
        return await self._stub.StartHTTPListener(http_req, timeout=timeout)

    async def start_https_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 443,
        website: str = "",
        domain: str = "",
        cert: bytes = b"",
        key: bytes = b"",
        acme: bool = False,
        persistent: bool = False,
        enforce_otp: bool = True,
        randomize_jarm: bool = True,
        long_poll_timeout: int = 1,
        long_poll_jitter: int = 2,
        timeout: int = TIMEOUT,
    ) -> client_pb2.HTTPListener:
        """Start an HTTPS C2 listener

        :param domain: Domain name for HTTPS server (one domain per listener)
        :type domain: str
        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param website: Name of the "website" to host on listener
        :type website: str
        :param cert: TLS certificate (leave blank to generate self-signed certificate)
        :type cert: bytes
        :param key: TLS private key (leave blank to generate self-signed certificate)
        :type key: bytes
        :param acme: Automatically provision TLS certificate using ACME (i.e., Let's Encrypt)
        :type acme: bool
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param enforce_otp: Enforce OTP auth for HTTPS C2, defaults to True
        :type enforce_otp: bool, optional
        :param randomize_jarm: Randomize JARM fingerprint for HTTPS C2, defaults to True
        :type randomize_jarm: bool, optional
        :param long_poll_timeout: Long poll timeout for HTTPS C2, defaults to 1
        :type long_poll_timeout: int, optional
        :param long_poll_jitter: Long poll jitter for HTTPS C2, defaults to 2
        :type long_poll_jitter: int, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        """
        https_req = client_pb2.HTTPListenerReq(
            Domain=domain,
            Host=host,
            Port=port,
            Secure=True,
            Website=website,
            Cert=cert,
            Key=key,
            ACME=acme,
            Persistent=persistent,
            EnforceOTP=enforce_otp,
            LongPollTimeout=long_poll_timeout,
            LongPollJitter=long_poll_jitter,
            RandomizeJARM=randomize_jarm,
        )
        return await self._stub.StartHTTPSListener(https_req, timeout=timeout)

    async def start_tcp_stager_listener(
        self, host: str, port: int, data: bytes, timeout=TIMEOUT
    ) -> client_pb2.StagerListener:
        """Start a TCP stager listener

        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param data: Binary data of stage to host on listener
        :type data: bytes
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf StagerListener object
        :rtype: client_pb2.StagerListener
        """
        stage_req = client_pb2.StagerListenerReq(
            Protocol=client_pb2.TCP,
            Host=host,
            Port=port,
            Data=data,
        )
        return await self._stub.StartTCPStagerListener(stage_req, timeout=timeout)

    async def start_http_stager_listener(
        self,
        host: str,
        port: int,
        data: bytes,
        timeout: int = TIMEOUT,
    ) -> client_pb2.StagerListener:
        """Start an HTTP stager listener

        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param data: Binary data of stage to host on listener
        :type data: bytes
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf StagerListener object
        :rtype: client_pb2.StagerListener
        """
        stage_req = client_pb2.StagerListenerReq(
            Protocol=client_pb2.HTTP, Host=host, Port=port, Data=data
        )
        return await self._stub.StartHTTPStagerListener(stage_req, timeout=timeout)

    async def start_https_stager_listener(
        self,
        host: str,
        port: int,
        data: bytes,
        cert: bytes,
        key: bytes,
        acme: bool,
        timeout: int = TIMEOUT,
    ) -> client_pb2.StagerListener:
        """Start an HTTPS stager listener

        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param data: Binary data of stage to host on listener
        :type data: bytes
        :param cert: TLS certificate, leave blank to start listener as HTTP
        :type cert: bytes
        :param key: TLS key, leave blank to start listener as HTTP
        :type key: bytes
        :param acme: Automatically provision TLS certificate using ACME (i.e., Let's Encrypt)
        :type acme: bool
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf StagerListener object
        :rtype: client_pb2.StagerListener
        """
        stage_req = client_pb2.StagerListenerReq(
            Protocol=client_pb2.HTTPS,
            Host=host,
            Port=port,
            Data=data,
            Cert=cert,
            Key=key,
            ACME=acme,
        )
        return await self._stub.StartHTTPStagerListener(stage_req, timeout=timeout)

    async def generate_implant(
        self, config: client_pb2.ImplantConfig, timeout: int = 360
    ) -> client_pb2.Generate:
        """Generate a new implant using a given configuration

        :param config: Protobuf ImplantConfig object
        :type config: client_pb2.ImplantConfig
        :param timeout: gRPC timeout, defaults to 360
        :type timeout: int, optional
        :return: Protobuf Generate object containing the generated implant
        :rtype: client_pb2.Generate
        """
        req = client_pb2.GenerateReq(Config=config)
        return await self._stub.Generate(req, timeout=timeout)

    async def regenerate_implant(
        self, implant_name: str, timeout=TIMEOUT
    ) -> client_pb2.Generate:
        """Regenerate an implant binary given the implants "name"

        :param implant_name: The name of the implant to regenerate
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Generate object
        :rtype: client_pb2.Generate
        """
        regenerate = client_pb2.RegenerateReq(ImplantName=implant_name)
        return await self._stub.Regenerate(regenerate, timeout=timeout)

    async def implant_builds(
        self, timeout=TIMEOUT
    ) -> Dict[str, client_pb2.ImplantConfig]:
        """Get information about historical implant builds

        :return: Protobuf Map object, the keys are implant names the values are implant configs
        :rtype: Dict[str, client_pb2.ImplantConfig]
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        builds: client_pb2.ImplantBuilds = await self._stub.ImplantBuilds(
            common_pb2.Empty(), timeout=timeout
        )
        return dict(builds.Configs)

    async def delete_implant_build(self, implant_name: str, timeout=TIMEOUT) -> None:
        """Delete a historical implant build from the server by name

        :param implant_name: The name of the implant build to delete
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        delete = client_pb2.DeleteReq(Name=implant_name)
        await self._stub.DeleteImplantBuild(delete, timeout=timeout)

    async def canaries(self, timeout=TIMEOUT) -> List[client_pb2.DNSCanary]:
        """Get a list of canaries that have been generated during implant builds, includes metadata about those canaries

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of Protobuf DNSCanary objects
        :rtype: List[client_pb2.DNSCanary]
        """
        canaries = await self._stub.Canaries(common_pb2.Empty(), timeout=timeout)
        return list(canaries.Canaries)

    async def generate_wg_client_config(
        self, timeout=TIMEOUT
    ) -> client_pb2.WGClientConfig:
        """Generate a new WireGuard client configuration files

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf WGClientConfig object
        :rtype: client_pb2.WGClientConfig
        """
        return await self._stub.GenerateWGClientConfig(
            common_pb2.Empty(), timeout=timeout
        )

    async def generate_wg_ip(self, timeout=TIMEOUT) -> client_pb2.UniqueWGIP:
        """Generate a unique IP address for use with WireGuard

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf UniqueWGIP object
        :rtype: client_pb2.UniqueWGIP
        """
        return await self._stub.GenerateUniqueIP(common_pb2.Empty(), timeout=timeout)

    async def implant_profiles(
        self, timeout=TIMEOUT
    ) -> List[client_pb2.ImplantProfile]:
        """Get a list of all implant configuration profiles on the server

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of Protobuf ImplantProfile objects
        :rtype: List[client_pb2.ImplantProfile]
        """
        profiles = await self._stub.ImplantProfiles(common_pb2.Empty(), timeout=timeout)
        return list(profiles.Profiles)

    async def delete_implant_profile(self, profile_name, timeout=TIMEOUT) -> None:
        """Delete an implant configuration profile by name

        :param profile_name: Name of the profile to delete
        :type profile_name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        delete = client_pb2.DeleteReq()
        delete.Name = profile_name
        await self._stub.DeleteImplantProfile(delete, timeout=timeout)

    async def save_implant_profile(
        self, profile: client_pb2.ImplantProfile, timeout=TIMEOUT
    ) -> client_pb2.ImplantProfile:
        """Save an implant configuration profile to the server

        :param profile: An implant configuration profile (a Protobuf ImplantProfile object)
        :type profile: client_pb2.ImplantProfile
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf ImplantProfile object
        :rtype: client_pb2.ImplantProfile
        """
        return await self._stub.SaveImplantProfile(profile, timeout=timeout)

    async def generate_msf_stager(
        self,
        arch: str,
        format: str,
        host: str,
        port: int,
        os: str,
        protocol: client_pb2.StageProtocol.ValueType,
        badchars: Optional[Iterable[str]],
        timeout: int = TIMEOUT,
    ) -> client_pb2.MsfStager:
        """Create a Metasploit stager (if available on the server)

        :param arch: CPU architecture
        :type arch: str
        :param format: Binary format (MSF)
        :type format: str
        :param host: LHOST (MSF)
        :type host: str
        :param port: LPORT (MSF)
        :type port: int
        :param os: Operating System (MSF)
        :type os: str
        :param protocol: Stager protocol (Protobuf StageProtocol object)
        :type protocol: client_pb2.StageProtocol
        :param badchars: Bad characters, defaults to []
        :type badchars: list, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf MsfStager object
        :rtype: client_pb2.MsfStager
        """
        stagerReq = client_pb2.MsfStagerReq(
            Arch=arch,
            Format=format,
            Host=host,
            Port=port,
            OS=os,
            Protocol=protocol,
            BadChars=badchars if badchars else [],
        )
        return await self._stub.MsfStage(stagerReq, timeout=timeout)

    async def shellcode(
        self, data: bytes, function_name: str, arguments: str = "", timeout=TIMEOUT
    ) -> client_pb2.ShellcodeRDI:
        """Generate Donut shellcode

        :param data: The DLL file to wrap in a shellcode loader
        :type data: bytes
        :param function_name: Function to call on the DLL
        :type function_name: str
        :param arguments: Arguments to the function called
        :type arguments: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf ShellcodeRDI object
        :rtype: client_pb2.ShellcodeRDI
        """
        shellReq = client_pb2.ShellcodeRDIReq(
            Data=data, FunctionName=function_name, Arguments=arguments
        )
        return await self._stub.ShellcodeRDI(shellReq, timeout=timeout)

    async def websites(self, timeout=TIMEOUT) -> List[client_pb2.Website]:
        """Get a list of websites

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of Protobuf Website objects
        :rtype: List[client_pb2.Website]
        """
        websites = await self._stub.Websites(common_pb2.Empty(), timeout=timeout)
        return list(websites.Websites)

    async def update_website(
        self, website: client_pb2.Website, timeout=TIMEOUT
    ) -> client_pb2.Website:
        """Update an entire website object on the server

        :param website: The updated Protobuf Website object
        :type website: client_pb2.Website
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        """
        return await self._stub.Websites(website, timeout=timeout)

    async def remove_website(self, name: str, timeout=TIMEOUT) -> None:
        """Remove an entire website and its content

        :param name: The name of the website to remove
        :type name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        """
        website = client_pb2.Website(Name=name)
        await self._stub.WebsiteRemove(website, timeout=timeout)

    async def add_website_content(
        self,
        name: str,
        web_path: str,
        content_type: str,
        content: bytes,
        timeout: int = TIMEOUT,
    ) -> client_pb2.Website:
        """Add content to a specific website

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        """
        web = client_pb2.WebContent(
            Path=web_path, ContentType=content_type, Content=content, Size=len(content)
        )

        web_add = client_pb2.WebsiteAddContent(Name=name, Contents={web_path: web})
        return await self._stub.WebsiteAddContent(web_add, timeout=timeout)

    async def update_website_content(
        self,
        name: str,
        web_path: str,
        content_type: str,
        content: bytes,
        timeout: int = TIMEOUT,
    ) -> client_pb2.Website:
        """Update content on a specific website / web path

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        """
        web = client_pb2.WebContent(
            Path=web_path, ContentType=content_type, Content=content, Size=len(content)
        )

        web_update = client_pb2.WebsiteAddContent(Name=name, Contents={web_path: web})
        return await self._stub.WebsiteUpdateContent(web_update, timeout=timeout)

    async def remove_website_content(
        self, name: str, paths: List[str], timeout=TIMEOUT
    ) -> client_pb2.Website:
        """Remove content from a specific website

        :param name: The name of the website from which to remove the content
        :type name: str
        :param paths: A list of paths to content that should be removed from the website
        :type paths: List[str]
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        """
        web = client_pb2.WebsiteRemoveContent(Name=name, Paths=paths)
        return await self._stub.WebsiteRemoveContent(web, timeout=timeout)
