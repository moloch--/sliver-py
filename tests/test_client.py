import os
from pathlib import Path

from ward import fixture, test, skip

from sliver import SliverClient, SliverClientConfig
from sliver.pb.clientpb.client_pb2 import (
    ImplantC2,
    ImplantConfig,
    ImplantProfile,
    OutputFormat,
    StageProtocol,
)


@fixture(scope="global")
async def sliver_client() -> SliverClient:
    CONFIG_PATH = Path("~/.sliver-client/configs/sliverpy.cfg").expanduser()
    config = SliverClientConfig.parse_config_file(CONFIG_PATH)
    client = SliverClient(config)
    await client.connect()
    return client


@fixture(scope="global")
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


@fixture(scope="global")
def sliverpy_random_name() -> str:
    return "sliver-pytest-" + os.urandom(8).hex()


@fixture(scope="global")
def data_dir() -> Path:
    return Path(__file__).parent / "data"


@test("**Client can get version**")
async def _(client: SliverClient = sliver_client):
    assert await client.version()


@test("Client can list operators")
async def _(client: SliverClient = sliver_client):
    assert await client.operators()


@test("Client can list beacons")
async def _(client: SliverClient = sliver_client):
    assert await client.beacons()


@test("Client can list beacons by ID")
async def _(client: SliverClient = sliver_client):
    beacons = await client.beacons()
    assert await client.beacon_by_id(beacons[0].ID)


@test("Client can rename a beacon")
async def _(client: SliverClient = sliver_client):
    beacons = await client.beacons()
    beacon_name = beacons[0].Name
    beacon_id = beacons[0].ID
    await client.rename_beacon(beacon_id, "sliver-pytest")

    beacon = await client.beacon_by_id(beacon_id)
    assert beacon.Name == "sliver-pytest"

    await client.rename_beacon(beacon.ID, beacon_name)


@test("Client can list sessions")
async def _(client: SliverClient = sliver_client):
    assert await client.sessions()


@test("Client can list sessions by ID")
async def _(client: SliverClient = sliver_client):
    sessions = await client.sessions()
    assert await client.session_by_id(sessions[0].ID)


@test("Client can rename a session")
async def _(client: SliverClient = sliver_client):
    sessions = await client.sessions()
    session_name = sessions[0].Name
    session_id = sessions[0].ID
    await client.rename_session(session_id, "sliver-pytest")

    session = await client.session_by_id(session_id)
    assert session.Name == "sliver-pytest"

    await client.rename_session(session.ID, session_name)


@test("Client can list implant builds")
async def _(client: SliverClient = sliver_client):
    assert await client.implant_builds()


@test("Client can generate a new implant")
async def _(
    client: SliverClient = sliver_client, config: ImplantConfig = implant_config
):

    assert await client.generate_implant(config)


@test("Client can regenerate an implant")
async def _(
    client: SliverClient = sliver_client, config: ImplantConfig = implant_config
):
    assert await client.regenerate_implant(config.Name)


@test("Client can save implant profiles")
async def _(
    client: SliverClient = sliver_client,
    config: ImplantConfig = implant_config,
    name: str = sliverpy_random_name,
):
    implant_profile = ImplantProfile(Name=name, Config=config)
    assert await client.save_implant_profile(implant_profile)


@test("Client can list implant profiles")
async def _(client: SliverClient = sliver_client, name: str = sliverpy_random_name):
    assert name in [profile.Name for profile in await client.implant_profiles()]


@test("Client can delete implant profiles")
async def _(client: SliverClient = sliver_client, name: str = sliverpy_random_name):
    await client.delete_implant_profile(name)
    assert name not in [profile.Name for profile in await client.implant_profiles()]


@test("Client can delete implant builds")
async def _(
    client: SliverClient = sliver_client,
    config: ImplantConfig = implant_config,
):
    await client.delete_implant_build(config.Name)
    assert config.Name not in [build for build in await client.implant_builds()]


@test("Client can list jobs")
async def _(client: SliverClient = sliver_client):
    assert await client.jobs()


@test("Client can get job by ID")
async def _(client: SliverClient = sliver_client):
    jobs = await client.jobs()
    assert await client.job_by_id(jobs[0].ID)


@test("Client can get job by port")
async def _(client: SliverClient = sliver_client):
    assert await client.job_by_port(80)


@test("Client can kill jobs")
async def _(client: SliverClient = sliver_client):
    jobs = await client.jobs()
    for job in jobs:
        if job.Port != 80:
            await client.kill_job(job.ID)
    assert len(await client.jobs()) == 1


@test("Client can start HTTP listener on port 8080")
async def _(client: SliverClient = sliver_client):
    assert await client.start_http_listener()


@test("Client can start HTTPS listener on port 8443")
async def _(client: SliverClient = sliver_client):
    assert await client.start_https_listener()


@test("Client can start DNS listener on port 53")
async def _(client: SliverClient = sliver_client):
    assert await client.start_dns_listener(domains=["sliverpy.local"])


@test("Client can start MTLS listener on port 8888")
async def _(client: SliverClient = sliver_client):
    assert await client.start_mtls_listener()


@test("Client can start TCP stager listener on port 9000")
async def _(client: SliverClient = sliver_client):
    assert await client.start_tcp_stager_listener("0.0.0.0", 9000, b"sliver-pytest")


@test("Client can start HTTP stager listener on port 9001")
async def _(client: SliverClient = sliver_client):
    assert await client.start_http_stager_listener("0.0.0.0", 9001, b"sliver-pytest")


@skip("Cert generation not implemented")
@test("Client can start HTTPS stager listener on port 9002")
async def _(client: SliverClient = sliver_client):
    assert await client.start_http_stager_listener("0.0.0.0", 9002, b"sliver-pytest")


@test("Client can generate a WireGuard IP")
async def _(client: SliverClient = sliver_client):
    assert await client.generate_wg_ip()


@skip("Something is wrong with killing WG listeners on the server")
@test("Client can start WG listener on ports 5353/8889/1338")
async def _(client: SliverClient = sliver_client):
    ip = await client.generate_wg_ip()
    print(ip.IP)
    assert await client.start_wg_listener(ip.IP, 5353, 8889, 1338)


@test("Client can generate a WireGuard client config")
async def _(client: SliverClient = sliver_client):
    assert await client.generate_wg_client_config()


@test("Client can kill jobs (again) except WireGuard")
async def _(client: SliverClient = sliver_client):
    jobs = await client.jobs()
    for job in jobs:
        if job.Port != 80:
            await client.kill_job(job.ID)
    assert len(await client.jobs()) <= 2


@test("Client can generate an MSF stager")
async def _(client: SliverClient = sliver_client):
    assert await client.generate_msf_stager(
        arch="amd64",
        format="raw",
        host="127.0.0.1",
        port=9000,
        os="windows",
        protocol=StageProtocol.TCP,
        badchars=[],
    )


@test("Client can generate Donut shellcode")
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):
    dll_data = Path(data_dir / "test_write.exe").read_bytes()
    assert await client.shellcode(dll_data, "Main")


@test("Client can interact with a session")
async def _(client: SliverClient = sliver_client):
    sessions = await client.sessions()
    session = sessions[0]
    assert await client.interact_session(session.ID)


@test("Client can interact with a beacon")
async def _(client: SliverClient = sliver_client):
    beacons = await client.beacons()
    beacon = beacons[0]
    assert await client.interact_beacon(beacon.ID)


@test("Client can add website content")
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):
    html_content = Path(data_dir / "website.html").read_bytes()
    assert await client.add_website_content(
        "sliverpy-test", "sliverpy", "test/html", html_content
    )


@test("Client can update website content")
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):
    html_content = Path(data_dir / "website_update.html").read_bytes()
    assert await client.add_website_content(
        "sliverpy-test", "sliverpy", "test/html", html_content
    )


@test("Client can list websites")
async def _(client: SliverClient = sliver_client):
    assert "sliverpy-test" in [website.Name for website in await client.websites()]


@test("Client can remove website content")
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):
    assert await client.remove_website_content("sliverpy-test", ["sliverpy"])


@test("Client can remove website")
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):
    await client.remove_website("sliverpy-test")
    assert "sliverpy-test" not in [website.Name for website in await client.websites()]
