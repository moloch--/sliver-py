import os
from dataclasses import dataclass
from pathlib import Path

from ward import Scope, fixture

from sliver import InteractiveSession, SliverClient, SliverClientConfig
from sliver.pb.clientpb.client_pb2 import ImplantC2, ImplantConfig, OutputFormat


@dataclass
class TestConstants:
    """Dataclass for customizable constants used in testing (e.g. listener
    ports)"""

    op_cfg_file: str
    implant_profile_name: str
    multiplayer_job_name: str
    wg_job_name: str
    multiplayer_job_port: int
    listen_addr: str
    http_listen_port: int
    https_listen_port: int
    dns_listen_port: int
    dns_domain: str
    mtls_listen_port: int
    stager_listen_port: int  # will be incremented by 1 for each stager listener test
    stager_data: bytes
    wg_listen_ports: list

    # below are for interactive tests
    mkdir_path: str
    file_path: str
    file_data: bytes
    env_var: str
    env_value: str


@fixture(scope=Scope.Global)
def test_constants() -> TestConstants:
    rand_string = "sliver-pytest-" + os.urandom(8).hex()

    test_const = TestConstants(
        op_cfg_file="~/.sliver-client/configs/sliverpy.cfg",
        implant_profile_name=f"{rand_string}",
        multiplayer_job_name="grpc",
        wg_job_name="wg",
        multiplayer_job_port=31337,
        listen_addr="0.0.0.0",
        http_listen_port=8787,
        https_listen_port=8443,
        dns_listen_port=5300,
        dns_domain="sliverpy.local",
        mtls_listen_port=8899,
        stager_listen_port=9000,
        stager_data=b"sliver-pytest",
        wg_listen_ports=[5553, 8889, 1338],
        # below are for interactive tests
        mkdir_path=f"/tmp/{rand_string}",
        file_path=f"/tmp/{rand_string}.txt",
        file_data=bytes(rand_string, "utf8"),
        env_var=f"SLIVERPY_TEST_{rand_string}",
        env_value=rand_string,
    )
    return test_const


@fixture(scope=Scope.Global)
async def sliver_client(const: TestConstants = test_constants) -> SliverClient:
    cfg_path = Path(const.op_cfg_file).expanduser()
    config = SliverClientConfig.parse_config_file(cfg_path)
    client = SliverClient(config)
    await client.connect()
    return client


@fixture(scope=Scope.Global)
async def extant_jobs(client: SliverClient = sliver_client) -> list:  # type: ignore
    # Keep a list of jobs already running, so we don't kill them
    jobs = await client.jobs()
    print(jobs)
    return jobs


@fixture(scope=Scope.Global)
async def implant_config() -> ImplantConfig:
    return ImplantConfig(
        IsBeacon=False,
        Name="sliver-pytest-" + os.urandom(8).hex(),
        GOARCH="amd64",
        GOOS="linux",
        Format=OutputFormat.EXECUTABLE,
        ObfuscateSymbols=False,
        C2=[ImplantC2(Priority=0, URL="http://localhost:80")],
    )


@fixture(scope=Scope.Module)
async def session_zero(client: SliverClient = sliver_client) -> InteractiveSession:  # type: ignore
    sessions = await client.sessions()
    for sess in sessions:
        if not sess.IsDead:
            break

    return await client.interact_session(sess.ID)  # type: ignore


@fixture(scope=Scope.Test)
def sliverpy_random_name() -> str:
    return "sliver-pytest-" + os.urandom(8).hex()


@fixture(scope=Scope.Global)
def data_dir() -> Path:
    return Path(__file__).parent / "data"
