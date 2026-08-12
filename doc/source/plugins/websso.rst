======
WebSSO
======

The ``v3websso`` plugin authenticates by sending the user to their browser. It
opens the identity service's WebSSO endpoint, the user authenticates there
against whichever identity provider the deployment has configured, and the
resulting unscoped token is delivered back to a listener the plugin runs on a
loopback port.

This suits interactive command line use, where the identity provider needs to
show the user a login page, prompt for a second factor, or reuse an existing
browser session. It needs no client credentials of its own.

About the protocol
==================

WebSSO is not a standardised protocol and has no RFC. The identity service
defined it so that Horizon could authenticate users against an external
identity provider, and modelled it on the SAML 2.0 Web Browser SSO Profile: as
in that profile's HTTP POST binding, the identity service responds with an
auto-submitting HTML form that posts the credential to a pre-registered,
trusted origin.

Because the identity service compares that origin against its configured list
of trusted origins verbatim, the callback path and the default port are not
values this plugin is free to choose. Both are taken from the Horizon and
identity service federation installation guides so that an existing deployment
works unchanged.

Server configuration
====================

The callback URL must be listed in the identity service's
``trusted_dashboard`` option, exactly as the plugin sends it:

.. code-block:: ini

    [federation]
    trusted_dashboard = http://localhost:9990/auth/websso/

The comparison is a string match, so a URL that differs only by a missing
trailing slash or a different port is rejected. If you change
``redirect-port`` or ``redirect-host``, add the matching URL here too.

The identity provider and protocol also have to be configured for federation.
See the `identity service federation documentation
<https://docs.openstack.org/keystone/latest/admin/federation/introduction.html>`_.

Usage
=====

Command line
------------

For an unscoped token:

.. code-block:: bash

    openstack --os-auth-url https://keystone.example.org:5000/v3 \
      --os-auth-type v3websso \
      --os-identity-provider <identity-provider> \
      --os-protocol openid \
      --os-identity-api-version 3 \
      token issue

This opens your browser at the identity provider, waits for the callback, and
prints the resulting token. For a project scoped token, add the usual scope
options:

.. code-block:: bash

    openstack --os-auth-url https://keystone.example.org:5000/v3 \
      --os-auth-type v3websso \
      --os-identity-provider <identity-provider> \
      --os-protocol openid \
      --os-project-name <project> \
      --os-project-domain-name <project-domain> \
      --os-identity-api-version 3 \
      token issue

Environment variables
---------------------

.. code-block:: bash

    export OS_AUTH_TYPE=v3websso
    export OS_AUTH_URL=https://keystone.example.org:5000/v3
    export OS_IDENTITY_PROVIDER=<identity-provider>
    export OS_PROTOCOL=openid
    export OS_PROJECT_NAME=<project-name>
    export OS_PROJECT_DOMAIN_NAME=<domain-name>

    openstack token issue

``clouds.yaml``
---------------

.. code-block:: yaml

    clouds:
      my_cloud:
        auth_type: v3websso
        auth:
          auth_url: https://keystone.example.org:5000/v3
          identity_provider: <identity-provider>
          protocol: openid
          project_name: <project-name>
          project_domain_name: <domain-name>

Then:

.. code-block:: bash

    OS_CLOUD=my_cloud openstack token issue

Python
------

.. code-block:: python

    from keystoneauth1 import session
    from keystoneauth1.identity import v3

    auth = v3.WebSSO(
        auth_url='https://keystone.example.org:5000/v3',
        identity_provider='my-idp',
        protocol='openid',
        project_name='my-project',
        project_domain_name='Default',
    )
    sess = session.Session(auth=auth)

Token caching
=============

The flow needs a browser, so it cannot be repeated without a graphical session
and it cannot be repeated silently. To keep that from happening on every
command, the plugin caches the *unscoped* token on disk.

The cache key covers the auth URL, the identity provider and the protocol. It
deliberately does **not** cover the scope, so a single browser login can be
rescoped to any project the user has access to:

.. code-block:: bash

    # authenticates in a browser
    openstack --os-project-name project-a server list

    # reuses the cached unscoped token, no browser
    openstack --os-project-name project-b server list

The default location follows the platform's user cache directory:

============  ==============================================
Linux         ``$XDG_CACHE_HOME/keystoneauth/websso/``, or
              ``~/.cache/keystoneauth/websso/``
macOS         ``~/Library/Caches/keystoneauth/websso/``
Windows       ``%LOCALAPPDATA%\keystoneauth\websso\``
============  ==============================================

Set ``cache-path`` to override it. Cache files are created with user-only
permissions (``0600``) in a user-only directory (``0700``), and a cached token
is discarded once it is close to expiring. A cache file that cannot be read or
parsed is removed and ignored rather than treated as an error.

Controlling the cache
---------------------

``token-cache`` selects what to do with the cache:

``reuse``
  The default. Reuse a cached token when one is available.

``refresh``
  Discard the cached token, authenticate in a browser again, and cache the
  result. Use this when the cached token is known to be bad, for example after
  it has been revoked. The old token is removed before the flow starts, so a
  failed login cannot leave it behind to be picked up later.

``disabled``
  Neither read nor write the cache. Every command needs a browser round trip.

.. code-block:: bash

    # the cached token is bad; get a new one and replace it
    openstack --os-auth-type v3websso --os-token-cache refresh ... token issue

``refresh`` is a one time action rather than something to configure
permanently: setting it in ``clouds.yaml`` would force a browser round trip on
every command. Note also that the values are words rather than ``true`` and
``false`` because YAML reads several English words as booleans, which would
make ``token_cache: no`` in ``clouds.yaml`` mean something other than it says.

A revoked token does not usually need any of this. When a request comes back
unauthorized the session invalidates the plugin and retries, and that discards
the cached token along with the in-memory one, so the next attempt authenticates
afresh.

Security notes
==============

The listener receives a bearer token over plain HTTP on a loopback port, so it
is deliberately restrictive:

- It only binds to loopback addresses. A ``redirect-host`` that resolves to
  anything else is rejected, so the token is never accepted on a network
  interface.
- It accepts a single POST of ``application/x-www-form-urlencoded`` at
  ``/auth/websso/`` with a bounded body, and ignores everything else.
- It requires the `Fetch Metadata
  <https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header>`_
  headers to describe a top-level document navigation, which is the shape the
  identity service's auto-submitting form produces. This rejects ``fetch()``
  and ``XMLHttpRequest``, which would otherwise reach the listener because a
  form content type makes them "simple" cross-origin requests needing no
  preflight.
- When ``Origin`` or ``Referer`` identifies an origin, it must be the identity
  service's. Both are frequently unusable, as described below.

The received token is always validated against the identity service before it
is used.

.. warning::

   **The callback is open to login CSRF.** While a login is in progress, any
   page open in the user's browser can submit a form to the callback port and
   have its own token accepted, leaving the user operating as whoever obtained
   that token.

   None of the checks above prevent this, because nothing in the request
   distinguishes it from the identity service's own POST:

   - A scripted cross-origin form submission sends exactly the same
     ``Sec-Fetch-Mode: navigate``, ``Sec-Fetch-Dest: document`` and
     ``Sec-Fetch-Site: cross-site`` as the auto-submitted form does. Only
     ``fetch()`` and ``XMLHttpRequest`` are excluded.
   - On the HTTPS-to-HTTP callback this flow depends on, the `Fetch standard
     <https://fetch.spec.whatwg.org/#append-a-request-origin-header>`_
     serializes ``Origin`` as ``null`` and the default referrer policy drops
     ``Referer`` entirely. Both are therefore absent or uninformative for a
     genuine POST *and* for an attacker's, so neither can be required.

   This cannot be fixed within the protocol. Binding the callback to the
   request it belongs to needs a nonce, and there is nowhere to put one: the
   identity service requires the ``origin`` parameter to match a
   ``trusted_dashboard`` entry exactly, so it cannot carry per-request data.

   What limits the exposure is the size of the window. The listener binds to
   loopback only, runs only while a login is in progress, stops at the first
   token it accepts, and times out. Treat an unexpected browser window or a
   session that comes back as the wrong user as a reason to revoke the token.

Troubleshooting
===============

Port already in use
-------------------

Choose another port with ``--os-redirect-port``, and add the matching callback
URL to ``trusted_dashboard``:

.. code-block:: bash

    openstack --os-auth-type v3websso --os-redirect-port 9991 ... token issue

The browser does not open
-------------------------

The URL is always logged at warning level before the browser is launched, so it
can be opened or copied manually. This is not conditional on the launch
failing: the standard library reports success whenever it finds something to
launch, which on a remote shell or a minimal desktop is not the same as the user
reaching the page.

The URL is written to the log, and therefore to standard error, rather than to
standard output, so it does not interfere with parsing machine readable output
such as ``-f json``. Consumers that configure logging can route or suppress it
like any other keystoneauth message.

The token is never received
---------------------------

Check that the callback port is not blocked locally, that the
``trusted_dashboard`` entry matches the callback URL exactly, and that the
identity provider is correctly configured on the identity service.

Credits
=======

This plugin is derived from the ``keystoneauth-oidc`` plugin originally
developed by the Spanish National Research Council and INDIGO-DataCloud, and is
licensed under the Apache License 2.0.
