Getting Started
===============

To get started first download the `latest Sliver server release <https://github.com/BishopFox/sliver/releases/latest>`_ 
you'll need v1.5 or later to use SliverPy.

SliverPy connects to the Sliver server using "multiplayer mode" which can be enabled in the server console or using
the Sliver server's command line interface. In order to connect to the server you'll need to first generate an operator 
configuration file. Clients connect to the Sliver server using mutual TLS (mTLS) and these operator configuration files 
contain the per-user TLS certificates (and other metadata) needed to make the connection to the server. These configuration
files contain the user's private key and should be treated as if they were a credential.

In the interactive console, the ``new-operator`` command is used to generate an operator configuration file. You'll need to 
subsequently enable multiplayer mode using the ``multiplayer`` command to start the multiplayer server listener. See the 
``--help`` for each of these commands for more details:

.. code-block:: console

    $ ./sliver-server

    sliver > new-operator --name zer0cool --lhost localhost --save ./zer0cool.cfg
    [*] Generating new client certificate, please wait ...
    [*] Saved new client config to: /Users/zer0cool/zer0cool.cfg

    sliver > multiplayer
    [*] Multiplayer mode enabled!


Alternatively, the command line interface can be used to generate operator configuration files and start the multiplayer listener
without entering into the interactive console. See each subcommand's ``--help`` for more details:

.. code-block:: console

    $ ./sliver-server operator --name zer0cool --lhost localhost --save ./zer0cool.cfg
    $ ./sliver-server daemon


Now with the server running in the background you can connect to Sliver remotely (or locally) using the ``.cfg`` with SliverPy!

Connect Example
^^^^^^^^^^^^^^^^

SliverPy is implemented using ``asyncio``, if you're unfamiliar with Python's ``asyncio`` you may want to go read up on it before continuing. 
I recommend starting with `this presentation <https://www.youtube.com/watch?v=9zinZmE3Ogk>`_ by Raymond Hettinger if you're completely unfamiliar with Python threads/asyncio.

The main class is ``SliverClient``, which when paired with a configuration file, allows you to interact with the Sliver server, sessions, and beacons:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    CONFIG_PATH = os.path.join('path', 'to', 'default.cfg')

    async def main():
        ''' Async client connect example '''
        config = SliverClientConfig.parse_config_file(CONFIG_PATH)
        client = SliverClient(config)
        await client.connect()
        sessions = await client.sessions()
        print('Sessions: %r' % sessions)

    if __name__ == '__main__':
        asyncio.run(main())


Protobuf / gRPC
^^^^^^^^^^^^^^^

Under the hood SliverPy is communicating with the Sliver server using `Protobuf <https://developers.google.com/protocol-buffers/docs/pythontutorial>`_ and 
`gRPC <https://grpc.io/docs/languages/python/basics/>`_. While most of the details of these libraries are abstracted for you, it may be useful to familiarize 
yourself with the library conventions as SliverPy operates largely on Protobuf objects which do not follow Python language conventions.

There are three modules of Protobuf objects:

- ``sliver.commonpb_pb2`` Contains common Protobuf objects that represent things like files and processes.
- ``sliver.client_pb2``  Contains objects that are specifically passed between the client and server, but *not* to the implant.
- ``sliver.sliver_pb2`` Contains objects that are passed to the client, server, and implant.

**NOTE:** Protobuf objects use ``CapitolCase`` whereas the SliverPy classes/etc. use ``snake_case``.

These modules contain generated code and are not easy to read. However, the source Protobuf definitions are in the `Sliver server repository <https://github.com/BishopFox/sliver/tree/master/protobuf>`_ 
to find the exact definitions that SliverPy is using see the `git submodule <https://github.com/moloch--/sliver-py>`_ in the SliverPy repository.


Interactive Sessions
^^^^^^^^^^^^^^^^^^^^

To interact with a Sliver session we need to create an ``InteractiveSession`` object, the easiest way to do this is using the ``SliverClient``'s 
``.interact_session()`` method, which takes a session ID and returns an ``InteractiveSession`` for that ID:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    # Construct path to operator config file
    CONFIG = os.path.join('path', 'to', 'operator.cfg')

    async def main():
        ''' Session interact example '''
        config = SliverClientConfig.parse_config_file(CONFIG)
        client = SliverClient(config)
        await client.connect()
        sessions = await client.sessions()  # <-- List Protobuf Session objects
        if not len(sessions):
            print('No sessions!')
            return

        session = await client.interact_session(sessions[0].ID)  # <-- Create InteractiveSession object
        ls = await session.ls()                                  # <-- Returns an Ls Protobuf object
        print('Listing directory contents of: %s' % ls.Path)
        for fi in ls.Files:
            print('FileName: %s (dir: %s, size: %d)' % (fi.Name, fi.IsDir, fi.Size))

    if __name__ == '__main__':
        main()

**NOTE:** There are two "session" related objects the Protobuf ``client_pb2.Session`` object, which contains metadata about the sessions such as
the session ID, the active C2 protocol, etc. and the ``InteractiveSession`` class, which is used to interact with the session (i.e., execute commands, etc).


Interactive Beacons
^^^^^^^^^^^^^^^^^^^^

To interact with a Sliver beacon we need to create an ``InteractiveBeacon`` object, the easiest way to do this is using the ``SliverClient``'s 
``.interact_beacon()`` method, which takes a beacon ID and returns an ``InteractiveBeacon`` for that ID:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    # Construct path to operator config file
    CONFIG = os.path.join('path', 'to', 'operator.cfg')

    async def main():
        ''' Session interact example '''
        config = SliverClientConfig.parse_config_file(CONFIG)
        client = SliverClient(config)
        await client.connect()
        beacons = await client.beacons()  # <-- List Protobuf Session objects
        if not len(beacons):
            print('No beacons!')
            return

        beacon = await client.interact_beacon(beacons[0].ID)  # <-- Create InteractiveSession object
        ls_task = await beacon.ls()                           # <-- Creates a beacon task Future
        print('Created beacon task: %s' % ls_task)
        print('Waiting for beacon task to complete ...')
        ls = await ls_task

        # Beacon Task has completed (Future was resolved)
        print('Listing directory contents of: %s' % ls.Path)
        for fi in ls.Files:
            print('FileName: %s (dir: %s, size: %d)' % (fi.Name, fi.IsDir, fi.Size))


    if __name__ == '__main__':
        main()

**NOTE:** The main difference between interacting with a session vs. a beacon, is that a beacon's command will return a ``Future`` object that eventually resolves to the task result.


Realtime Events
^^^^^^^^^^^^^^^^

SliverPy also supports realtime events, which are pushed from the server to the client whenever an event occurs. For example, some of the more common events you'll likely
be interested in are when a new session is created or when a job starts/stops. 

The :class:`SliverClient` implements these real time events using ``asyncio``.  

Events are identified by an "event type," which is just a string set by the producer of the event. This loose form
allows events to be very dynamic, however this also means there is no central authority for every event type. I 
recommend always filtering on expected event types. The data included in an event also depends on whatever produced
the event, so you should always check that an attribute exists before accessing that attribute (with the exception of 
``event.EventType`` which must exist).

Here is a non exhaustive list of event types:

+--------------------------+-----+----------------------------------------------------+
| Event Type               |     | Description                                        |
+--------------------------+-----+----------------------------------------------------+
| ``session-disconnected`` |     | An existing session was lost                       |
+--------------------------+-----+----------------------------------------------------+
| ``session-updated``      |     | An existing session was renamed / updated          |
+--------------------------+-----+----------------------------------------------------+
| ``job-started``          |     | A job was started on the server                    |
+--------------------------+-----+----------------------------------------------------+
| ``job-stopped``          |     | A job stopped (due to error or user action)        |
+--------------------------+-----+----------------------------------------------------+
| ``client-joined``        |     | A new client connected to the server               |
+--------------------------+-----+----------------------------------------------------+
| ``client-left``          |     | A client disconnected from the server              |
+--------------------------+-----+----------------------------------------------------+
| ``canary``               |     | A canary was burned / triggered / etc.             |
+--------------------------+-----+----------------------------------------------------+
| ``build``                |     | A modification was made to implant builds          |
+--------------------------+-----+----------------------------------------------------+
| ``build-completed``      |     | An implant build completed (in success or failure) |
+--------------------------+-----+----------------------------------------------------+
| ``profile``              |     | A modification was made to implant profiles        |
+--------------------------+-----+----------------------------------------------------+
| ``website``              |     | A modification was made to website(s)              |
+--------------------------+-----+----------------------------------------------------+
| ``beacon-registered``    |     | A new beacon connected to the server               |
+---------------------------+---------------------------------------------------------+
| ``beacon-taskresult``    |     | A beacon task completed                            |
+---------------------------+---------------------------------------------------------+


Automatically Interact With New Sessions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Realtime events in :class:`AsyncSliverClient` work differently than in :class:`SliverClient`.

Instead of callbacks, ``.on()`` returns an async generator, which can be iterated over. The async version of
``.on()`` accepts a string or a list of strings to filter events. Additionally, ``.events()`` can be used to
obtain a generator that will yield all events.

Here is an example of using ``.on()`` to automatically interact with new sessions when they connect:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    import asyncio
    from sliver import SliverClientConfig, AsyncSliverClient, client_pb2

    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
    DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")


    async def main():
        ''' Client connect example '''
        config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
        client = AsyncSliverClient(config)
        await client.connect()
        async for event in client.on('session-connected'):
            print('Automatically interacting with session %s' % event.Session.ID)
            interact = await client.interact(event.Session.ID)
            exec_result = await interact.execute('whoami', [], True)
            print('Exec %r' % exec_result)

    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())


SliverPy should integrate well with any framework that supports ``asyncio``, but doing so is left
as an exercise for the reader.
