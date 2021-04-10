Sliver Py
==========

Sliver Py (pronounced "sliver pie") is a Python gRPC client library for Sliver.


__NOTE:__ This is not a full featured client library (yet)


## Examples

#### List Sessions / Async List Sessions
```python
#!/usr/bin/env python3

import os
import asyncio
from sliver import SliverClientConfig, SliverClient, SliverAsyncClient

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
    client = SliverAsyncClient(config)
    await client.connect()
    sessions = await client.sessions()
    print('[async] Sessions: %r' % sessions)

if __name__ == '__main__':
    main()
    asyncio.run(run())
```


#### Interact with Session
```python
#!/usr/bin/env python3

import os
from sliver import SliverClientConfig, SliverClient, SliverAsyncClient

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")


def main():
    ''' Client example '''
    config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
    client = SliverClient(config)
    client.connect()
    sessions = client.sessions()
    if len(sessions):
        interact = client.interact(sessions[0].ID)
        print('Interacting with session %d', interact.session_id)
        print('ls: %r', interact.ls())

if __name__ == '__main__':
    main()
```