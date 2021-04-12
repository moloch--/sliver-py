Getting Started
===============

To get started first download the `latest Sliver server release <https://github.com/BishopFox/sliver/releases/latest>`_ 
you'll need v1.4.11 or later to use SliverPy.

SliverPy connects to the Sliver server using "multiplayer mode" which can be enabled in the server console or using
the command line interface. In order to connect to the server you'll need an operator configuration file.

Using the interactive console use the ``new-player`` command to generate an operator configuration file and then enable
multiplayer mode using the ``multiplayer`` command:

.. code-block:: console

    $ ./sliver-server

    sliver > new-player --operator zer0cool --lhost localhost --save ./operator.cfg
    [*] Generating new client certificate, please wait ...
    [*] Saved new client config to: /Users/zer0cool/operator.cfg

    sliver > multiplayer
    [*] Multiplayer mode enabled!


Alternatively, using the command line interface:

.. code-block:: console

    $ ./sliver-server operator --name zer0cool --lhost localhost --save ./operator.cfg
    $ ./sliver-server daemon


Now leave the server running and you can connect to Sliver remotely (or locally) using the ``.cfg`` with SliverPy!

Client Connect
^^^^^^^^^^^^^^

You'll need to parse the ``.cfg`` using the ``SliverClientConfig`` the easiest way to do this is using the ``parse_config_file`` 
class method or you can pass the file content as a ``bytes`` to the ``parse_config``. Here is a basic example:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    # Construct path to operator config file
    CONFIG = os.path.join('path', 'to', 'operator.cfg')

    def main():
        ''' Client connect example '''
        config = SliverClientConfig.parse_config_file(CONFIG)
        client = SliverClient(config)
        client.connect()
        print('Sessions: %r' % client.sessions())

    if __name__ == '__main__':
        main()


Async Client Connect
^^^^^^^^^^^^^^^^^^^^

SliverPy also supports ``asyncio`` using the ``AsyncSliverClient`` class:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, AsyncSliverClient

    CONFIG = os.path.join('path', 'to', 'default.cfg')

    async def main():
        ''' Async client connect example '''
        config = SliverClientConfig.parse_config_file(CONFIG)
        client = AsyncSliverClient(config)
        await client.connect()
        sessions = await client.sessions()
        print('Sessions: %r' % sessions)

    if __name__ == '__main__':
        asyncio.run(main())


More about something.