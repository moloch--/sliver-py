Getting Started
===============

To get started first download the `latest Sliver server release <https://github.com/BishopFox/sliver/releases/latest>`_ 
you'll need v1.4.11 or later to use SliverPy.

SliverPy connects to the Sliver server using "multiplayer mode" which can be enabled in the server console or using
the Sliver server's command line interface. In order to connect to the server you'll need to first generate an operator 
configuration file. Clients connect to the Sliver server using mutual TLS (mTLS) and these operator configuration files 
contain the per-user TLS certificates (and other metadata) needed to make the connection to the server. These configuration
files contain the user's private key and should be treated as if they were a credential.

In the interactive console, the ``new-player`` command is used to generate an operator configuration file. You'll need to 
subsequently enable multiplayer mode using the ``multiplayer`` command to start the multiplayer server listener. See the 
``--help`` for each of these commands for more details:

.. code-block:: console

    $ ./sliver-server

    sliver > new-player --operator zer0cool --lhost localhost --save ./operator.cfg
    [*] Generating new client certificate, please wait ...
    [*] Saved new client config to: /Users/zer0cool/operator.cfg

    sliver > multiplayer
    [*] Multiplayer mode enabled!


Alternatively, the command line interface can be used to generate operator configuration files and start the multiplayer listener
without entering into the interactive console. See each subcommand's ``--help`` for more details:

.. code-block:: console

    $ ./sliver-server operator --name zer0cool --lhost localhost --save ./operator.cfg
    $ ./sliver-server daemon


Now with the server running in the background you can connect to Sliver remotely (or locally) using the ``.cfg`` with SliverPy!

Connect Example
^^^^^^^^^^^^^^^

First you'll need to load the ``.cfg`` using the ``SliverClientConfig`` class. The easiest way to do this is using the ``.parse_config_file()`` 
class method, or you can pass the file content as ``bytes`` to the ``.parse_config()`` class method if you don't want to specify the file path. 
Here is a basic example, just modify the ``CONFIG`` path to point to the ``operator.cfg`` we generated using the server:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    # Construct path to operator config file
    CONFIG = os.path.join('path', 'to', 'operator.cfg')

    def main():
        ''' Client connect example '''
        config = SliverClientConfig.parse_config_file(CONFIG) # <-- Class method
        client = SliverClient(config)
        client.connect()
        print('Sessions: %r' % client.sessions())

    if __name__ == '__main__':
        main()


**NOTE:** We're creating an instance of the ``SliverClientConfig`` using a Python class method (i.e., we do not need to instantiate the object to call
the method). If you want to directly create an instance if ``SliverClientConfig()`` you'll need to pass in the various configuration values yourself.
The ``SliverClientConfig.parse_config_file()`` class method essentially parses the configuration file and instantiates the class for us.


Async Connect Example
^^^^^^^^^^^^^^^^^^^^^

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


**NOTE:** The ``SliverClient`` and ``AsyncSliverClient`` classes both use the same ``SliverClientConfig`` for configuration.


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
``.interact()`` method, which takes a numeric session ID and returns an ``InteractiveSession`` for that ID:

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
        sessions = client.sessions()  # <-- List Protobuf Session objects
        if not len(sessions):
            print('No sessions!')
            return

        interact = client.interact(sessions[0].ID)  # <-- Create InteractiveSession object
        ls = interact.ls()                          # <-- Returns an Ls Protobuf object

        print('Listing directory contents of: %s' % ls.Path)
        for fi in ls.Files:
            print('FileName: %s (dir: %s, size: %d)' % (fi.Name, fi.IsDir, fi.Size))

    if __name__ == '__main__':
        main()

**NOTE:** There are two "session" related objects the Protobuf ``client_pb2.Session`` object, which contains metadata about the sessions such as
the session ID, the active C2 protocol, etc. and the ``InteractiveSession`` class, which is used to interact with the session (i.e., execute commands, etc).


Basic Event Example (Threads)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SliverPy also supports realtime events, which are pushed from the server to the client whenever an event occurs. Some of the more common events you'll likely
be interested in are when a new session is created, or when a job starts/stops. The :class:`SliverClient` provides several helpful abstractions to cut down
on event noise, by default you can register a callback to fire on every event or events specifically related to sessions, jobs, or canaries.

First, let's start with a basic callback that will be fired whenever any event occurs:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient, client_pb2

    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
    DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")


    def event_callback(event: client_pb2.Event):
        ''' This callback function is executed whenever an event occurs '''
        print('Event fired: %r' % event)

    def main():
        config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
        client = SliverClient(config)
        client.connect()

        client.on_event(event_callback)  # <-- Register callback function

        try:
            print('Ctrl+c to Exit\n\n')
            client.wait_for_events()   # <-- Blocks main thread
        except KeyboardInterrupt:
            print('Attempting to cleanup thread pool ...')
            client.stop_events()       # <-- Attempt to clean threads before exit

    if __name__ == '__main__':
        main()


**IMPORTANT:** Callback functions are executed in a thread pool and SliverPy provides NO THREAD SAFETY. You must implement any needed locks yourself.
However, it's *generally* safe to call :class:`SliverClient` methods in parallel since the client does not maintain much state.


Automatically Interact With New Sessions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A more practical example is to have our SliverPy program execute some logic/commands automatically whenever a new session is created on the server.
To do this we can register a callback function with `.on()` for the specific `session-connected` event:

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient, client_pb2

    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
    DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")


    def auto_interact(client: SliverClient, session: client_pb2.Session):
        ''' Interact with newly created session and perform some action '''
        print('Automatically interacting with session #%d' % session.ID)
        interact = client.interact(session.ID)
        exec = interact.execute('whoami', [], True)
        print('Exec %r' % exec)

    def main():
        ''' Client connect example '''
        config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
        client = SliverClient(config)
        client.connect()

        def session_callback(event: client_pb2.Event):
            ''' Pass client amd event.Session to auto_interact() '''
            auto_interact(client, event.Session)

        # Register callback function
        client.on("session-connected", session_callback)

        try:
            print('Waiting for sessions, Ctrl+c to Exit\n\n')
            client.wait_for_events()  # <-- Block main thread
        except KeyboardInterrupt:
            print('\rAttempting to cleanup thread pool ...')
            client.stop_events()

    if __name__ == '__main__':
        main()



Basic Event Example (Async)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO
