# SliverPy

SliverPy is a Python gRPC client library for [Sliver](https://github.com/BishopFox/sliver). SliverPy can be used to automate any operator interaction with Sliver and connects to servers using gRPC over Mutual TLS (i.e., multiplayer) using Sliver operator configuration files. [For more details, please see the project documentation](http://sliverpy.rtfd.io/).

⚠️ Not all features in Sliver v1.5+ are supported yet.

[![SliverPy](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml/badge.svg)](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml)
[![Documentation Status](https://readthedocs.org/projects/sliverpy/badge/?version=latest)](https://sliverpy.readthedocs.io/en/latest/?badge=latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

### Install

Install the package using pip, for best compatibility use Sliver Server v1.5.29 or later:

`pip3 install sliver-py`

## Examples

For more examples and details please read the [project documentation](http://sliverpy.rtfd.io/).

#### Interact with Sessions

```python
#!/usr/bin/env python3

import os
import asyncio
from sliver import SliverClientConfig, SliverClient

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")

async def main():
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = AsyncSliverClient(config)
    print('[*] Connected to server ...')
    await client.connect()
    sessions = await client.sessions()
    print('[*] Sessions: %r' % sessions)
    if len(sessions):
        print('[*] Interacting with session %s', sessions[0].ID)
        interact = await client.interact_session(sessions[0].ID)
        ls = await interact.ls()
        print('[*] ls: %r' % ls)

if __name__ == '__main__':
    asyncio.run(main())
```

#### Interact with Beacons

```python
#!/usr/bin/env python3

import os
import asyncio
from sliver import SliverClientConfig, SliverClient

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")

async def main():
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = SliverClient(config)
    print('[*] Connected to server ...')
    await client.connect()
    version = await client.version()
    print('[*] Server version: %s' % version)

    beacons = await client.beacons()
    print('[*] Beacons: %r' % beacons)
    if len(beacons):
        print('[*] Interacting with beacon: %r' % beacons[0].ID)
        interact = await client.interact_beacon(beacons[0].ID)
        ls_task = await interact.ls()
        print('[*] Created ls task: %r' % ls_task)
        print('[*] Waiting for task results ...')
        ls = await ls_task
        print('[*] ls: %r' % ls)

if __name__ == '__main__':
    asyncio.run(main())
```

## Development

The development environment has migrated to [hatch](https://github.com/pypa/hatch) and the installation instructions can be found [here](https://hatch.pypa.io/latest/install/).

### Note on VS Code

Unfortunately, VS Code does not automatically detect hatch virtual environments yet due to how it structures environments. However, you can make setting the Python interpreter path easier by including the virtual environment directly in the folder by running these commands before setting up the virtual environment:

```
hatch config set dirs.env.virtual .venv
hatch config update
```

### Setting up Hatch environment

Once installed, run `hatch -e dev shell` to enter the development environment. Hatch allows for scripts to be defined as well. These scripts are executed in the context of the defined environment. The current scripts defined are:


- `hatch run dev:fmt`  -- runs `black` and `isort` for formatting

### Docker/WSL2

A Dockerfile is included if you wish to develop inside a container. This may be preferable for development on any operating system to keep the dev environment isolated. Windows developers may choose to develop inside WSL2.

In either case, `scripts/sliver_install.sh` contains a modified version of the official Sliver installation script that does not create a `systemd` based service. After running this script, you may start a local Sliver server in your container or WSL2 instance by running:

`sudo /root/sliver-server daemon &`

Alternatively, you can still choose to set up an external Sliver instance to connect to via Sliver's [multi-player mode](https://github.com/BishopFox/sliver/wiki/Multiplayer-Mode). The `sliver_install` script is purely for local development convenience.

### Updating protobufs
This should only be necessary when changes are made to Sliver's protobuf. Running `scripts/protobufgen.py` will update `sliver-py` protobuf files. Ensure that the `.pyi` type hints are generated also.

### Running tests
To run all tests, you should have at least one beacon implant and one session implant connected to you Sliver instance. Currently, it is ok to only have them running on a Linux system (implants running on your sliver server works fine). In the future, you may need to have a session implant on the type of operating system the test is for, particularly for Windows.

Tests are implemented using [Ward](https://github.com/darrenburns/ward). The tests have been tagged so you can run all the tests or just the tests you need. Recommendation is to run all tests when making a major change.

Test parameters you may want to change (e.g. listener ports) are in `fixtures.py`.

- `ward` : All tests
- `ward --tags client`: Run all client tests - at least one beacon and one session (alive or dead)
must be present on the server
- `ward --tags interactive`: Run interactive operation tests - requires an active session on the server

Subsets of `client` tests:

- `connect`: connect & get server version only
- `server_info`: connect & get version, operator and jobs info
- `listeners`: test listeners
- `implant`: implant-related tests
- `website`: website-related tests
- `generate`: both implant & website tests
- `beacon`: test beacon manipulation - requires at least one beacon on server (alive or dead)
- `session`: test session manipulation - requires at least one session on server (alive or dead)

Additional interactive operation tags (not included by default because they can crash the implant on some targets, sometimes):

- `screenshot`: take a screenshot on the target system
- `memdump`: take a memory dump of the target system
- `interactive_full`: all `interactive` tests plus `screenshot` and `memdump`