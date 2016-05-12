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
the managesf REST API interface in Software Factory. It can be used to
administrate Software Factory, for example to manage projects and users.

Introduction
------------

Global options
''''''''''''''

By default all actions require authentication as well as some information about
the remote servers.

\--url <http://sfgateway.dom>
    URL of the managesf instance

\--auth user:password
    Username and password to use when accessing the managesf interface.
    This option is only valid if it is a local user within Software Factory

There are a few optional arguments as well:

\--insecure
    Disable SSL certificate verification. Enabled by default

\--debug
    Enable debug messages in console. Disabled by default


Example usage
'''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project create

Help
''''

Help is always available using the argument '-h':

.. code-block:: bash

 sfmanager project -h
 usage: sfmanager project [-h]
                          {delete_user,add_user,list_active_users,create,delete}
                          ...

.. _managesf_create_project:

Project management
------------------

Create new project
''''''''''''''''''

SF exposes ways to create and initialize projects in Redmine and Gerrit
simultaneously. Initializing a project involves setting up the ACL and
initializing the source repository.

Any user that can authenticate against SF will be able to create a project.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project create --name <project-name>

There are a few more options available in case you want to customize the
project.

\--description [project-description], -d [project-description]
    An optional description of the project.

\--upstream [GIT link], -u [GIT link]
    Uses the given repository to initalize the project, for example to reuse an existing Github repository

\--upstream-ssh-key upstream-ssh-key
    SSH key for upstream repository if authentication is required

\--core-group [core-group-members], -c [core-group-members]
    A list of comma-separated member ids that are setup as core reviewers. Core
    reviewers can approve or block patches; by default a review from at least
    one core is required to merge a patch.

\--ptl-group [ptl-group-members], -p [ptl-group-members]
    A list of comma-separated member ids that are setup as PTLs (Project
    Technical Lead). The members can give core permissions to other users.

\--dev-group [dev-group-members], -e [dev-group-members]
    A list of comma-separated member ids that are setup as developers of this
    project. Only required if a project is marked private.

\--private
    Mark project as private. In that case only members of the dev, core or ptl
    group are allowed to access the project.

Delete Project
''''''''''''''

SF exposes ways to delete projects and the groups associated with the project in
Redmine and Gerrit simultaneously.

For any project, only the PTLs shall have the permission to delete it.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           project delete --name <project-name>


Group management
----------------

Default groups
''''''''''''''

When a project is created a few default project groups are created. To modify
these groups a user needs to be at least in the same group of users.

projectname-ptl
    Group of PTLs. Members can add other users to all groups.
projectname-core
    Group of core reviewers. Members can add other users to the groups
    projectname-core and projectname-dev
projectname-dev
    Group of developers, required when project is private. Members can not add
    any other user to any group.

List project users
''''''''''''''''''

Currently only lists all known users. This command is useful for the "add"
subcommand of the membership command or for `--ptl-group`, `--core-group`,
`--dev-group` of the project create options.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership list


Add user to project groups
''''''''''''''''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership add --user user1@tests.dom --project p1 \
           --groups ptl-group core-group



Remove user from project groups
'''''''''''''''''''''''''''''''

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership remove --user user1@tests.dom --project p1 \
           --group ptl-group

If the request does not provide a specific group to delete the user from, SF
will remove the user from all groups associated to a project.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           membership remove --user user1@tests.dom --project p1


User management
---------------

These commands manage the local users, that are not using external
authentication systems like Github.


Add user
''''''''

Creates a new local user and registers the user in Gerrit and Redmine

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
'''''''''''

Update an existing local user. A user can update it's own details, and admins
can also update other user details. Takes the same arguments as user create.
The options `--fullname` and `--ssh-key` (if updated) won't be taken in account
inside SF services. Only the password can be updated.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user update --username jdoe --password unguessable


Delete user
'''''''''''

Disable the user's account. That does not prevent the user from contributing, it
only prevents the user from login in to Software Factory.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           user delete --username jdoe


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
'''''''''''''''''''

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


Restore a backup
''''''''''''''''

SF exposes ways to restore a backup of all the user data store in your
SF installation. This backup can be used in case of disaster to quickly
recover user data on the same or other SF installation (in the same version).

Only the SF administrator can restore a backup.

SF allows you to restore a backup in one of the following way.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
           system restore --filename sf_backup.tar.gz

Using GPG to encrypt and decrypt backups
''''''''''''''''''''''''''''''''''''''''

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

You have to copy this public key to the SF node, and import it as root user.

.. code-block:: bash

 scp sfadmin.pub root@sftests.com:.
 gpg --import sfadmin.pub

Now you have to trust the imported key.
.. code-block:: bash

 gpg --edit-key sfadmin
 # Enter "trust"
 # Choose option 5, then exit

If you need to restore from a backup, you need to decrypt the tar.gz file first.

.. code-block:: bash

 gpg sf_backup.tar.gz.gpg


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


Initiate the test pipeline
--------------------------

Once you create a project, you can initiate the project's tests into Software
Factory's pipeline. The result is a entry into the Software Factory's
configuration repository that will require review. It will also create
placeholder scripts in your project. To skip the generation of the placeholder
just add `--no-scripts`.

.. code-block:: bash

 sfmanager --url <http://sfgateway.dom> --auth user:password \
                tests init --project prj1
