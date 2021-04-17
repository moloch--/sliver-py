SliverPy
==========

SliverPy is a Python gRPC client library for [Sliver](https://github.com/BishopFox/sliver). SliverPy can be used to automate any operator interaction with Sliver and connects to servers using gRPC over Mutual TLS (i.e., multiplayer) using Sliver operator configuration files. [For more details, please see the project documentation](http://sliverpy.rtfd.io/).


[![SliverPy](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml/badge.svg)](https://github.com/moloch--/sliver-py/actions/workflows/autorelease.yml)
[![Documentation Status](https://readthedocs.org/projects/sliverpy/badge/?version=latest)](https://sliverpy.readthedocs.io/en/latest/?badge=latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

### Install

Install the package using pip, for best compatibility use Sliver Server v1.4.11 or later:

`pip3 install sliver-py`

## Examples

For more examples please read the [project documentation](http://sliverpy.rtfd.io/).

#### List Sessions / Async List Sessions
```python
#!/usr/bin/env python3

import os
import asyncio
from sliver import SliverClientConfig, SliverClient, AsyncSliverClient

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")


def main():
    ''' Client example '''
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = SliverClient(config)
    client.connect()
    print('Sessions: %r' % client.sessions())


async def run():
    ''' Async client example '''
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = AsyncSliverClient(config)
    await client.connect()
    sessions = await client.sessions()
    print('[async] Sessions: %r' % sessions)

if __name__ == '__main__':
    main()
    asyncio.run(run())
```
