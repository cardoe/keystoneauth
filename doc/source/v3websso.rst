===================================
V3 Web SSO OpenID Connect Plugin
===================================

Overview
========

The ``v3websso`` plugin provides browser-based authentication for OpenStack clients
using OpenID Connect (OIDC) Web Single Sign-On (SSO). This plugin is ideal for
interactive command-line usage where users can authenticate through their Identity
Provider's web interface.

Unlike other OIDC plugins that require client credentials or authorization codes,
this plugin automatically opens a web browser for user authentication and captures
the resulting token through a local callback server.

Features
========

- **Browser-based authentication**: Opens the default web browser for user login
- **Local callback server**: Automatically captures authentication tokens
- **Token caching**: Stores and reuses valid tokens to avoid repeated logins
- **Configurable callback**: Supports custom host and port for the callback server
- **Platform-independent cache**: Uses platform-specific cache directories

Installation
============

The v3websso plugin is included in keystoneauth1 and requires the following
additional dependencies:

- ``multipart>=1.0.0`` - For parsing form data from the callback
- ``platformdirs>=2.5.2`` - For platform-specific cache directory locations

These dependencies are automatically installed with keystoneauth1.

Server Configuration
====================

The Keystone server must be configured to support OpenID Connect federation.

Keystone Configuration
----------------------

Add trusted dashboard URLs to ``keystone.conf``:

.. code-block:: ini

    [federation]
    trusted_dashboard=http://your-horizon-dashboard/auth/websso/
    trusted_dashboard=http://localhost:9990/auth/websso/

.. note::
   The default callback URL is ``http://localhost:9990/auth/websso/``.
   If you change the ``redirect-port``, update the trusted_dashboard accordingly.

Apache Configuration
--------------------

Configure Apache to protect the WebSSO endpoint in ``wsgi-keystone.conf``:

**Global redirect endpoint:**

.. code-block:: apache

    <Location /v3/auth/OS-FEDERATION/identity_providers/redirect>
      AuthType openid-connect
      Require valid-user
    </Location>

**Identity Provider specific WebSSO endpoint:**

.. code-block:: apache

    <Location /v3/auth/OS-FEDERATION/identity_providers/<IDP-name>/protocols/openid/websso>
      Require valid-user
      AuthType openid-connect
      OIDCDiscoverURL http://localhost:15000/v3/auth/OS-FEDERATION/identity_providers/redirect?iss=<url-encoded-issuer>
    </Location>

Replace ``<IDP-name>`` with your Identity Provider name and ``<url-encoded-issuer>``
with the URL-encoded issuer URL.

For detailed mod_auth_openidc configuration with Keycloak or other OIDC providers,
consult the `OpenIDC documentation <https://github.com/OpenIDC/mod_auth_openidc/wiki>`_.

Usage
=====

Command Line - Unscoped Token
------------------------------

To obtain an unscoped token:

.. code-block:: bash

    openstack --os-auth-url https://keystone.example.org:5000/v3 \\
      --os-auth-type v3websso \\
      --os-identity-provider <identity-provider> \\
      --os-protocol openid \\
      --os-identity-api-version 3 \\
      token issue

This will:

1. Open your default web browser to the Identity Provider's login page
2. Start a local HTTP server on port 9990 waiting for the callback
3. After successful authentication, capture the token and display it

Command Line - Scoped Token
----------------------------

To obtain a project-scoped token:

.. code-block:: bash

    openstack --os-auth-url https://keystone.example.org:5000/v3 \\
      --os-auth-type v3websso \\
      --os-identity-provider <identity-provider> \\
      --os-protocol openid \\
      --os-project-name <project> \\
      --os-project-domain-name <project-domain> \\
      --os-identity-api-version 3 \\
      token issue

Environment Variables
---------------------

You can set environment variables instead of command-line arguments:

.. code-block:: bash

    export OS_AUTH_TYPE=v3websso
    export OS_AUTH_URL=https://keystone.example.org:5000/v3
    export OS_IDENTITY_PROVIDER='<keystone-identity-provider>'
    export OS_PROTOCOL=openid
    export OS_PROJECT_NAME='<project-name>'
    export OS_PROJECT_DOMAIN_NAME='<domain-name>'

    openstack token issue

clouds.yaml Configuration
--------------------------

For repeatable usage, configure authentication in ``clouds.yaml``:

**Unscoped authentication:**

.. code-block:: yaml

    clouds:
      my_cloud:
        auth_type: v3websso
        auth:
          auth_url: https://keystone.example.org:5000/v3
          identity_provider: <keystone-identity-provider>
          protocol: openid

**Scoped authentication:**

.. code-block:: yaml

    clouds:
      my_cloud:
        auth_type: v3websso
        auth:
          auth_url: https://keystone.example.org:5000/v3
          identity_provider: <keystone-identity-provider>
          protocol: openid
          project_name: <project-name>
          project_domain_name: <domain-name>

Then use it:

.. code-block:: bash

    OS_CLOUD=my_cloud openstack token issue

Python API
----------

Using the plugin programmatically:

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3

    # Create the WebSSO auth plugin
    auth = v3.WebSSOOpenIDConnect(
        auth_url='https://keystone.example.org:5000/v3',
        identity_provider='my-idp',
        protocol='openid',
        project_name='my-project',
        project_domain_name='Default',
        redirect_port=9990  # Optional, defaults to 9990
    )

    # Create a session
    sess = session.Session(auth=auth)

    # Make authenticated requests
    projects = sess.get('/v3/projects').json()

Configuration Options
=====================

The v3websso plugin supports the following configuration options:

Required Options
----------------

- ``auth-url``: Keystone endpoint URL (e.g., ``https://keystone.example.org:5000/v3``)
- ``identity-provider``: Name of the Identity Provider configured in Keystone
- ``protocol``: Authentication protocol (typically ``openid``)

Optional Options
----------------

- ``redirect-host``: Hostname for the callback server (default: ``localhost``)
- ``redirect-port``: Port for the callback server (default: ``9990``)
- ``cache-path``: Directory path for token cache (default: platform-specific cache directory)
- ``project-name`` / ``project-id``: Project to scope to
- ``project-domain-name`` / ``project-domain-id``: Domain containing the project
- ``domain-name`` / ``domain-id``: Domain to scope to

Token Caching
=============

The plugin automatically caches authentication tokens to avoid repeated browser
logins. Tokens are stored in a platform-specific cache directory:

- **Linux**: ``~/.cache/keystoneauth1/``
- **macOS**: ``~/Library/Caches/keystoneauth1/``
- **Windows**: ``%LOCALAPPDATA%\\keystoneauth1\\Cache\\``

Cache files are named based on the auth URL and identity provider, allowing
multiple configurations to be cached independently. Cache files are created
with user-only read/write permissions (mode 0600).

Tokens are automatically validated for expiration and will trigger
re-authentication when expired.

Troubleshooting
===============

Port Already in Use
-------------------

If port 9990 is already in use, specify a different port:

.. code-block:: bash

    openstack --os-auth-type v3websso \\
      --os-redirect-port 9991 \\
      ...

Or in ``clouds.yaml``:

.. code-block:: yaml

    clouds:
      my_cloud:
        auth_type: v3websso
        auth:
          # ... other settings ...
          redirect_port: 9991

Remember to add the new callback URL to Keystone's ``trusted_dashboard`` list.

Browser Does Not Open
---------------------

If the browser doesn't open automatically, the plugin will display a URL
that you can manually copy and paste into your browser.

Token Not Captured
------------------

If the token is not captured:

1. Ensure the callback server port is not blocked by a firewall
2. Verify the ``trusted_dashboard`` configuration in Keystone matches your redirect URL
3. Check that Apache's mod_auth_openidc is properly configured

References
==========

- `Original keystoneauth-websso plugin by VEXXHOST <https://github.com/vexxhost/keystoneauth-websso>`_
- `OpenID Connect specification <http://openid.net/specs/openid-connect-core-1_0.html>`_
- `mod_auth_openidc documentation <https://github.com/OpenIDC/mod_auth_openidc>`_
- `Keystone federation documentation <https://docs.openstack.org/keystone/latest/admin/federation/introduction.html>`_

Credits
=======

This plugin is based on the keystoneauth-websso project originally developed by:

- Spanish National Research Council
- INDIGO-DataCloud
- VEXXHOST

Licensed under the Apache License 2.0.
