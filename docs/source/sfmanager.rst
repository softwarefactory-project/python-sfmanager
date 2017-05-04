..
  Please note: if you change this file you need to rebuild the manpage using the
  following command and commit the manpage file too:

  sphinx-build -b man docs/source/ docs/man/
  git add docs/man/sfmanager.1
  git commit

.. toctree::

CLI for Software Factory
========================

This documentation describes the shell utility **sfmanager**, which is a CLI for
the managesf REST API interface in Software Factory..

Introduction
------------

Global options
^^^^^^^^^^^^^^

By default all actions require authentication as well as some information about
the remote servers.

\--url <http://sfgateway.dom>
    URL of the managesf instance

Optional:

\--insecure
    Disable SSL certificate verification.

\--debug
    Enable debug messages in console. Disabled by default

\--json
    Output command results as JSON, if applicable

Authentication
^^^^^^^^^^^^^^

\--auth user:password
    Username and password to use when accessing the managesf interface.
    This option is only valid if it is a local user within Software Factory

\--api-key abcde1234
    User API key that can be found on the user's settings page

\--cookie uid=...
    The HTTP auth cookie, can be found with the developer console in any
    web browser

\--github-token kkkk
    A Github API token, if the user is authenticating to Software Factory with
    his/her Github account

rc file
^^^^^^^

Rather than writing these global options each time the CLI is used, they can
be stored in $HOME/.software-factory.rc:

.. code-block:: yaml

 sf_environment:
    url: https://sftests.com
    insecure: true
    # use one of these auth methods at most. They are listed in priority order
    # in case several are present.
    auth:
      username: admin
      # password can be omitted if username is provided; it will have to be
      # manually set within the CLI
      password: userpass
      api-key: edcba
      cookie: nomnom
      github-token: abcde
    debug: false

If you are using distinct instances of Software Factory, more environments can
be defined in the rc file in the same fashion.

To apply an environment configuration, use:

.. code-block:: bash

 sfmanager -e sf_environment ...

User management
---------------

.. _user-management:

These commands manage the local users, that are not using external
authentication systems like Github.


Add user
^^^^^^^^

Creates a new user in the internal backend and registers the user in Gerrit and Redmine

\--username [username], -u [username]
    A unique username/login

\--password [password], -p [password]
    The user password, can be provided interactively if this option is empty

\--email [email], -e [email]
    The user email

\--fullname [John Doe], -f [John Doe]
    The user's full name, defaults to username

\--ssh-key [/path/to/pub_key], -s [/path/to/pub_key]
    The user's ssh public key file

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user create --username jdoe --password secret --fullname "User Tester" \
                --email jane@doe.org

Update user
^^^^^^^^^^^

Update an existing local user. A user can update it's own details, and admins
can also update other user details. Takes the same arguments as user create.
The options `--fullname` and `--ssh-key` (if updated) won't be taken in account
inside SF services. Only the password can be updated.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user update --username jdoe --password unguessable


Delete user
^^^^^^^^^^^

Disable the user's account. That does not prevent the user from contributing, it
only prevents the user from login in to Software Factory.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user delete --username jdoe


Registered User management
--------------------------

These commands manage the global users. Please note that these commands do not
modify users on Software Factory's local authentication backend.


Register user
^^^^^^^^^^^^^

Registers the user with all the services. The typical use
case is to provision a user before his or her first login on Software Factory,
so that project memberships can be set ahead of time.

\--username [username], -u [username]
    A unique username/login

\--email [email], -e [email]
    The user email

\--fullname [John Doe], -f [John Doe]
    The user's full name, defaults to username

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           sf_user create --username jdoe --fullname "User Tester" \
                --email jane@doe.org


Deregister user
^^^^^^^^^^^^^^^

This command removes the user from all the services. It does not delete a user
from the local authentication backend; the user can also register again simply
by logging into Software Factory. The typical use case is when a user experiences
a problem with external authentication, removing the user from the services and
relogging might be a solution.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           sf_user delete --username jdoe

or

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           sf_user delete --email jdoe@users.com

List registered users
^^^^^^^^^^^^^^^^^^^^^

This command lists all the users currently registered (ie who have logged in at
least once) on Software Factory.

For each user, the following information is returned:

* the username
* the user's full name
* the user's email
* the user's internal id within manageSF
* the user's id within cauth, the SSO system

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           sf_user list

.. _managesf_backup:

Backup and restore
------------------

Backups include database dumps from Gerrit, Jenkins, Mysql, cauth and managesf
as well as some important configuration files like Gerrit replication settings,
SSH keys and Hiera settings. This includes credentials; please see below how to
store backups encrypted. Because Mysql is used as the default backend in
Redmine, Paste and Etherpad all of this data is also included in the backup
file.

Create a new backup
^^^^^^^^^^^^^^^^^^^

SF exposes ways to perform and retrieve a backup of all the user data store in
your SF installation. This backup can be used in case of disaster to quickly
recover user data on the same or another SF installation (of the same version).

Only the SF administrator can perform and retrieve a backup.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system backup_start

Once the server generated the tar file of the backup you can then download it with
the following command

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system backup_get

A file called "sf_backup.tar.gz" will be created in the local directory.


Using GPG to encrypt and decrypt backups
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is recommended to store the backup files encrypted when using external
storage services, since the user and administrative credentials are included
in the backup.
When using the export_backup_swift.sh shell script included in SF, all backups
are automatically encrypted using GPG before uploading to Swift. A special
public GPG key is required for this, and it has to be stored on the SF node.
To create this key, do the following:

.. code-block:: bash

 gpg --gen-key  # Use "sfadmin" as name when creating the key
 gpg --export -a sfadmin > sfadmin.pub
 gpg --export-secret-key -a sfadmin > sfadmin.key

Make sure you copy keep the sfadmin.key in a safe place. For example, if it is
encrypted using a strong password store it alongside your backup files.

You have to copy this public key to the SF node, and import it as root user.

.. code-block:: bash

 scp sfadmin.pub root@sftests.com:.
 gpg --import sfadmin.pub

If you need to restore from a backup, you need to decrypt the tar.gz file first.

.. code-block:: bash

 gpg -d sf_backup.tar.gz.gpg


Request a password to access the Gerrit API
-------------------------------------------

To request a random password to access the Gerrit API for the current user. This
is useful for using tools like  `gertty <https://github.com/stackforge/gertty>`_ .

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_api_htpasswd generate_password

and to deactivates the password from Gerrit.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                gerrit_api_htpasswd delete_password
