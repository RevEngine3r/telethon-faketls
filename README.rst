Telethon MTProxy FakeTLS
========================
.. epigraph::

  ⭐️Thanks **everyone** who has starred the project, it means a lot!

TelethonFakeTLS adds support MTProxyFakeTLS Proxy (EE-secrets) to Telethon! (yes finally !!!)



What is this?
-------------

After long wait for Telethon to add support for EE proxy, i tired up and started implementing it myself !


Installing
----------

.. code-block:: sh

  pip3 install TelethonFakeTLS

Creating a client
-----------------
| You can use a base64 secret or hex one,
| But remember to
| Remove "ee" from the starting of hex secret
| And
| Remove "7" from the starting of the base64 secret.

.. code-block:: python

    Example:
    ee9b43b87555bf9464e02bdcd2db8932b07777772e736974652e636f6d -> 9b43b87555bf9464e02bdcd2db8932b07777772e736974652e636f6d
    7gEBAQEBAQEBAQEBAQEBAQFsaWIuYXJ2YW5jbG91ZC5jb20= -> gEBAQEBAQEBAQEBAQEBAQFsaWIuYXJ2YW5jbG91ZC5jb20=

.. code-block:: python

    import telethon.sync
    import TelethonFakeTLS

    api_id = 1234567
    api_hash = 'a1b2c3d4e5f6g7h8i9j9b8euryueusjj'

    proxy = ('195.201.142.247', 443, 'gEBAQEBAQEBAQEBAQEBAQFsaWIuYXJ2YW5jbG91ZC5jb20=')

    connection = TelethonFakeTLS.ConnectionTcpMTProxyFakeTLS
    proxy = proxy

    client = telethon.TelegramClient(
        session='test', api_id=api_id, api_hash=api_hash,
        connection=connection,
        proxy=proxy)

    client.start()


