# SliverPy

SliverPy is a Python gRPC client library for [Sliver](https://github.com/BishopFox/sliver). SliverPy can be used to automate any operator interaction with Sliver and connects to servers using gRPC over Mutual TLS (i.e., multiplayer) using Sliver operator configuration files. [For more details, please see the project documentation](http://sliverpy.rtfd.io/).

⚠️ Not all features in Sliver v1.5+ are supported yet.

[![SliverPy](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml/badge.svg)](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml)
[![Documentation Status](https://readthedocs.org/projects/sliverpy/badge/?version=latest)](https://sliverpy.readthedocs.io/en/latest/?badge=latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

### Install

Install the package using pip, for best compatibility use Sliver Server v1.5 or later:

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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
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

- `hatch run dev:genproto` -- executes `protobuf.sh` to generate new protobuf files based on Sliver submodule

### Docker/WSL2

A Dockerfile is included if you wish to develop inside a container. This may be preferable for development on any operating system to keep the dev environment isolated. Windows developers may choose to develop inside WSL2.

In either case, `scripts/sliver_install.sh` contains a modified version of the official Sliver installation script that does not create a `systemd` based service, as containers and WSL2 do not support systemd out of the box. After running this script, you may start a local Sliver server in your container or WSL2 instance by running:

`sudo /root/sliver-server daemon &`

Alternatively, you can still choose to set up an external Sliver instance to connect to via Sliver's [multi-player mode](https://github.com/BishopFox/sliver/wiki/Multiplayer-Mode). The `sliver_install` script is purely for local development convenience.
