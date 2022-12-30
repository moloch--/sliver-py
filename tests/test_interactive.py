from ward import test

from sliver.session import InteractiveSession

from .fixtures import TestConstants, session_zero, test_constants


@test(
    "InteractiveObject can send ping to server",
    tags=["interactive_full", "interactive"],
)
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ping()


@test("InteractiveObject can list processes", tags=["interactive_full", "interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ps()


@test(
    "InteractiveObject can get network interfaces",
    tags=["interactive_full", "interactive"],
)
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ifconfig()


@test(
    "InteractiveObject can get network connections",
    tags=["interactive_full", "interactive"],
)
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.netstat(True, True, True, True, True)


@test(
    "InteractiveObject can get working directory",
    tags=["interactive_full", "interactive"],
)
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.pwd()


@test("InteractiveObject can list directory", tags=["interactive_full", "interactive"])
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.ls()


@test(
    "InteractiveObject can make a directory", tags=["interactive_full", "interactive"]
)
async def _(
    session: InteractiveSession = session_zero, test_const: TestConstants = test_constants  # type: ignore
):
    assert await session.mkdir(test_const.mkdir_path)


@test(
    "InteractiveObject can change directory (depends on mkdir succeeding)",
    tags=["interactive_full", "interactive"],
)
async def _(session: InteractiveSession = session_zero, test_const: TestConstants = test_constants):  # type: ignore
    prev_dir = await session.pwd()
    assert await session.cd(test_const.mkdir_path)
    assert await session.cd(prev_dir.Path)


@test("InteractiveObject can upload a file", tags=["interactive_full", "interactive"])
async def _(
    session: InteractiveSession = session_zero,
    test_const: TestConstants = test_constants,
):
    assert await session.upload(test_const.file_path, test_const.file_data)


@test(
    "InteractiveObject can download files (depends on file upload succeeding)",
    tags=["interactive_full", "interactive"],
)
async def _(
    session: InteractiveSession = session_zero,  # type: ignore
    test_const: TestConstants = test_constants,  # type: ignore
):
    assert await session.download(test_const.file_path, True)


@test(
    "InteractiveObject can remove a directory (depends on mkdir succeeding)",
    tags=["interactive_full", "interactive"],
)
async def _(
    session: InteractiveSession = session_zero, test_const: TestConstants = test_constants  # type: ignore
):
    assert await session.rm(test_const.mkdir_path, recursive=True, force=True)


@test(
    "InteractiveObject can set an environment variable",
    tags=["interactive_full", "interactive"],
)
async def _(
    session: InteractiveSession = session_zero, test_const: TestConstants = test_constants  # type: ignore
):
    assert await session.set_env(test_const.env_var, test_const.env_value)


@test(
    "InteractiveObject can get an environment variable",
    tags=["interactive_full", "interactive"],
)
async def _(
    session: InteractiveSession = session_zero, test_const: TestConstants = test_constants  # type: ignore
):
    assert await session.get_env(test_const.env_var)


@test(
    "InteractiveObject can unset an environment variable",
    tags=["interactive_full", "interactive"],
)
async def _(
    session: InteractiveSession = session_zero, test_const: TestConstants = test_constants  # type: ignore
):
    assert await session.unset_env(test_const.env_var)


@test(
    "InteractiveObject can take a screenshot", tags=["interactive_full", "screenshot"]
)
async def _(session: InteractiveSession = session_zero):  # type: ignore
    assert await session.screenshot()


@test("InteractiveObject can take a memory dump", tags=["interactive_full", "memdump"])
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
