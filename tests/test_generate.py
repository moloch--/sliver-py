from pathlib import Path

import grpc.aio
from ward import test

from sliver import SliverClient
from sliver.pb.clientpb.client_pb2 import ImplantConfig, ImplantProfile, StageProtocol

from .fixtures import (
    TestConstants,
    data_dir,
    implant_config,
    sliver_client,
    test_constants,
)


@test("Client can generate a new implant", tags=["client", "generate", "implant"])
async def _(
    client: SliverClient = sliver_client, config: ImplantConfig = implant_config  # type: ignore
):

    assert await client.generate_implant(config)


@test("Client can list implant builds", tags=["client", "generate", "implant"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.implant_builds()


@test("Client can regenerate an implant", tags=["client", "generate", "implant"])
async def _(
    client: SliverClient = sliver_client, config: ImplantConfig = implant_config  # type: ignore
):
    assert await client.regenerate_implant(config.Name)


@test("Client can save implant profiles", tags=["client", "generate", "implant"])
async def _(
    client: SliverClient = sliver_client,  # type: ignore
    config: ImplantConfig = implant_config,  # type: ignore
    test_const: TestConstants = test_constants,  # type: ignore
):
    implant_profile = ImplantProfile(
        Name=test_const.implant_profile_name, Config=config
    )
    assert await client.save_implant_profile(implant_profile)


@test("Client can list implant profiles", tags=["client", "generate", "implant"])
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    name = test_const.implant_profile_name
    assert name in [profile.Name for profile in await client.implant_profiles()]


@test("Client can delete implant profiles", tags=["client", "generate", "implant"])
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    name = test_const.implant_profile_name
    await client.delete_implant_profile(name)
    assert name not in [profile.Name for profile in await client.implant_profiles()]


@test("Client can delete implant builds", tags=["client", "generate", "implant"])
async def _(
    client: SliverClient = sliver_client,  # type: ignore
    config: ImplantConfig = implant_config,  # type: ignore
):
    await client.delete_implant_build(config.Name)
    assert config.Name not in [build for build in await client.implant_builds()]


@test(
    "Client can generate an MSF stager (if msfvenom is available)",
    tags=["client", "generate", "implant"],
)
async def _(client: SliverClient = sliver_client):  # type: ignore
    try:
        stager = await client.generate_msf_stager(
            arch="amd64",
            format="raw",
            host="127.0.0.1",
            port=9000,
            os="windows",
            protocol=StageProtocol.TCP,
            badchars=[],
        )
        assert Path(stager.File.Name)

    except grpc.aio.AioRpcError as rpc_err:
        # don't fail if server is missing msfvenom
        assert rpc_err.details().find("executable file not found")


@test("Client can generate Donut shellcode", tags=["client", "generate", "implant"])
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):  # type: ignore
    dll_data = Path(data_dir / "test_write.exe").read_bytes()
    assert await client.shellcode(dll_data, "Main")


@test("Client can add website content", tags=["client", "generate", "website"])
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):  # type: ignore
    html_content = Path(data_dir / "website.html").read_bytes()
    assert await client.add_website_content(
        "sliverpy-test", "sliverpy", "test/html", html_content
    )


@test("Client can update website content", tags=["client", "generate", "website"])
async def _(client: SliverClient = sliver_client, data_dir: Path = data_dir):  # type: ignore
    html_content = Path(data_dir / "website_update.html").read_bytes()
    assert await client.add_website_content(
        "sliverpy-test", "sliverpy", "test/html", html_content
    )


@test("Client can list websites", tags=["client", "generate", "website"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert "sliverpy-test" in [website.Name for website in await client.websites()]


@test("Client can remove website content", tags=["client", "generate", "website"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.remove_website_content("sliverpy-test", ["sliverpy"])


@test("Client can remove website", tags=["client", "generate", "website"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    await client.remove_website("sliverpy-test")
    assert "sliverpy-test" not in [website.Name for website in await client.websites()]
