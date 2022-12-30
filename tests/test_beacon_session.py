from ward import test

from sliver import SliverClient

from .fixtures import sliver_client, sliverpy_random_name


@test("Client can list beacons", tags=["client", "beacon"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.beacons()


@test("Client can list beacons by ID", tags=["client", "beacon"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    beacons = await client.beacons()
    assert await client.beacon_by_id(beacons[0].ID)


@test("Client can rename a beacon", tags=["client", "beacon"])
async def _(client: SliverClient = sliver_client, rand_name: str = sliverpy_random_name):  # type: ignore
    beacons = await client.beacons()
    beacon_name = beacons[0].Name
    beacon_id = beacons[0].ID
    await client.rename_beacon(beacon_id, rand_name)

    beacon = await client.beacon_by_id(beacon_id)
    assert beacon.Name == rand_name

    await client.rename_beacon(beacon.ID, beacon_name)


@test("Client can interact with a beacon", tags=["client", "beacon"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    beacons = await client.beacons()
    beacon = beacons[0]
    assert await client.interact_beacon(beacon.ID)


@test("Client can list sessions", tags=["client", "session"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.sessions()


@test("Client can list sessions by ID", tags=["client", "session"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    sessions = await client.sessions()
    assert await client.session_by_id(sessions[0].ID)


@test("Client can rename a session", tags=["client", "session"])
async def _(client: SliverClient = sliver_client, rand_name: str = sliverpy_random_name):  # type: ignore
    sessions = await client.sessions()
    session_name = sessions[0].Name
    session_id = sessions[0].ID
    await client.rename_session(session_id, rand_name)

    session = await client.session_by_id(session_id)
    assert session.Name == rand_name

    await client.rename_session(session.ID, session_name)


@test("Client can interact with a session", tags=["client", "session"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    sessions = await client.sessions()
    session = sessions[0]
    assert await client.interact_session(session.ID)
