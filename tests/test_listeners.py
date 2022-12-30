from ward import skip, test

from sliver import SliverClient

from .fixtures import TestConstants, extant_jobs, sliver_client, test_constants


@test(
    "Client can list jobs (also initializes list of extant jobs not to kill)",
    tags=["client", "listeners", "kill"],
)
async def _(client: SliverClient = sliver_client, extant_jobs: list = extant_jobs):  # type: ignore
    print(extant_jobs)
    assert await client.jobs()


@test(
    "Client can start HTTP listener on specified port",
    tags=["client", "listeners", "kill"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_http_listener(port=test_const.http_listen_port)


@test(
    "Client can start HTTPS listener on specified port",
    tags=["client", "listeners"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_https_listener(port=test_const.https_listen_port)


@test("Client can start DNS listener on specified port", tags=["client", "listeners"])
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_dns_listener(
        port=test_const.dns_listen_port, domains=[test_const.dns_domain]
    )


@test(
    "Client can start MTLS listener on specified port",
    tags=["client", "listeners"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_mtls_listener(port=test_const.mtls_listen_port)


@test(
    "Client can start TCP stager listener on specified port",
    tags=["client", "listeners"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_tcp_stager_listener(
        test_const.listen_addr, test_const.stager_listen_port, test_const.stager_data
    )


@test(
    "Client can start HTTP stager listener on specified ports",
    tags=["client", "listeners"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_http_stager_listener(
        test_const.listen_addr,
        test_const.stager_listen_port + 1,
        test_const.stager_data,
    )


@skip("Cert generation not implemented")
@test(
    "Client can start HTTPS stager listener on specified ports",
    tags=["client", "listeners"],
)
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    assert await client.start_http_stager_listener(
        test_const.listen_addr,
        test_const.stager_listen_port + 2,
        test_const.stager_data,
    )


@test("Client can generate a WireGuard IP", tags=["client", "listeners"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.generate_wg_ip()


@skip("Something is wrong with killing WG listeners on the server")
@test("Client can start WG listener on specified ports", tags=["client", "listeners"])
async def _(client: SliverClient = sliver_client, test_const: TestConstants = test_constants):  # type: ignore
    ip = await client.generate_wg_ip()
    print(ip.IP)
    assert await client.start_wg_listener(
        ip.IP,
        test_const.wg_listen_ports[0],
        test_const.wg_listen_ports[1],
        test_const.wg_listen_ports[2],
    )


@test("Client can generate a WireGuard client config", tags=["client", "listeners"])
async def _(client: SliverClient = sliver_client):  # type: ignore
    assert await client.generate_wg_client_config()


@test("Client can kill jobs", tags=["client", "listeners", "kill"])
async def _(client: SliverClient = sliver_client, extant_jobs: list = extant_jobs):  # type: ignore
    jobs = await client.jobs()
    for job in jobs:
        found = False
        for extant in extant_jobs:
            if job.ID == extant.ID:
                found = True
                break

        if not found:
            await client.kill_job(job.ID)

    jobs_remain = await client.jobs()
    assert len(jobs_remain) == len(extant_jobs)
