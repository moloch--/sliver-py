from ward import fixture, test

from sliver import SliverClient
from sliver.session import InteractiveSession

from .test_client import sliver_client, sliverpy_random_name


@fixture(scope="module")
async def session_zero(client: SliverClient = sliver_client) -> InteractiveSession:  # type: ignore
    sessions = await client.sessions()
    return await client.interact_session(sessions[0].ID)  # type: ignore


@test("InteractiveObject can send ping to server", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ping()


@test("InteractiveObject can list processes", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ps()


@test("InteractiveObject can get network interfaces", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ifconfig()


@test("InteractiveObject can get network connections", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.netstat(True, True, True, True, True)


@test("InteractiveObject can get working directory", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.pwd()


@test("InteractiveObject can list directory", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ls()


@test("InteractiveObject can change directory", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.cd(".")


@test("InteractiveObject can make a directory", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero, target_dir: str = sliverpy_random_name  # type: ignore
):
    assert await session.mkdir(target_dir)


@test("InteractiveObject can upload a file", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero,  # type: ignore
    target_dir: str = sliverpy_random_name,  # type: ignore
):
    assert await session.upload(target_dir + "/sliverpy.txt", b"sliverpy")


@test("InteractiveObject can download files", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero,  # type: ignore
    target_dir: str = sliverpy_random_name,  # type: ignore
):
    assert await session.download(target_dir, True)


@test("InteractiveObject can remove a directory", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero, path: str = sliverpy_random_name  # type: ignore
):
    assert await session.rm(path, recursive=True, force=True)


@test("InteractiveObject can set an environment variable", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero, value: str = sliverpy_random_name  # type: ignore
):
    assert await session.set_env("SLIVERPY_TEST", value)


@test("InteractiveObject can get an environment variable", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero, value: str = sliverpy_random_name  # type: ignore
):
    assert await session.get_env(value)


@test("InteractiveObject can unset an environment variable", tags=["interactive"])
async def _(
    session: InteractiveSession = session_zero, value: str = sliverpy_random_name  # type: ignore
):
    assert await session.unset_env(value)


@test("InteractiveObject can take a screenshot", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.screenshot()


@test("InteractiveObject can take a memory dump", tags=["interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    procs = await session.ps()
    found_process = False
    for proc in procs[::-1]:
        if proc.Owner == session.username:
            dump = await session.process_dump(proc.Pid)
            if len(dump.Data) > 0:
                found_process = True
                break
    assert found_process
