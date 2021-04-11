Getting Started
===============

Getting started info...



Client Connect
^^^^^^^^^^^^^^

.. code-block:: python

    #!/usr/bin/env python3

    import os
    from sliver import SliverClientConfig, SliverClient

    # Construct path to operator config file
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".sliver-client", "configs")
    DEFAULT_CONFIG = os.path.join(CONFIG_DIR, "default.cfg")

    def main():
        ''' Client connect example '''
        config = SliverClientConfig.parse_config_file(DEFAULT_CONFIG)
        client = SliverClient(config)
        client.connect()
        print('Sessions: %r' % client.sessions())

    if __name__ == '__main__':
        main()


Foobar