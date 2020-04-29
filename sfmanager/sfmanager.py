#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import getpass
import glob
import json
import logging
import os
import re
import git
import requests
import sqlite3
import shlex
import subprocess
import sys
import time
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import yaml
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from prettytable import PrettyTable

from . import sfauth

JSON_OUTPUT = False
VERIFY_SSL = True
REQUESTS_PARAMS = {'cookies': None,
                   'headers': None}

DEFAULT_RC_PATHS = [os.path.join(os.getcwd(), '.software-factory.rc'),
                    os.path.expanduser('~/.software-factory.rc'),
                    os.path.expanduser('~/.software-factory/'
                                       'software-factory.rc'),
                    '/etc/software-factory/software-factory.rc']


logger = logging.getLogger('sfmanager')
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


def request(http_method, url, json=None, stream=False):
    return requests.request(http_method, url=url, verify=VERIFY_SSL,
                            json=json, stream=stream, **REQUESTS_PARAMS)


def _build_path(old_path):
    path = old_path
    if not os.path.isabs(path):
        homebase = os.path.expanduser('~')
        path = os.path.join(homebase, path)
    return path


def _is_cookie_valid(cookie):
    if not cookie:
        return False
    try:
        valid_until = float(cookie.split('%3B')[1].split('%3D')[1])
    except Exception:
        return False
    if valid_until < time.time():
        return False
    return True


def get_chromium_cookie(path='', host='softwarefactory'):
    jar_path = _build_path(path)
    logger.debug('looking for chrome cookies at %s' % jar_path)
    # chrome hardcoded values
    salt = b'saltysalt'
    iv = b' ' * 16
    length = 16
    chrome_password = 'peanuts'.encode('utf8')
    iterations = 1
    key = PBKDF2(chrome_password, salt, length, iterations)
    try:
        c = sqlite3.connect(jar_path)
        cur = c.cursor()
        cur.execute('select value, encrypted_value, host_key from cookies '
                    'where host_key like ? and name = "auth_pubtkt" '
                    'order by expires_utc desc',
                    ('%' + host + '%',))
        cypher = AES.new(key, AES.MODE_CBC, IV=iv)
        # Strip padding by taking off number indicated by padding
        # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.

        def clean(x):
            return x[:-ord(x[-1])].decode('utf8')

        for clear, encrypted, host_key in cur.fetchall():
            if clear:
                cookie = clear
            else:
                # buffer starts with 'v10'
                encrypted = encrypted[3:]
                try:
                    cookie = clean(cypher.decrypt(encrypted))
                except UnicodeDecodeError:
                    logger.debug("could not decode cookie %s" % encrypted)
                    cookie = None
            if _is_cookie_valid(cookie):
                return cookie
    except sqlite3.OperationalError as e:
        logger.debug("Could not read cookies: %s" % e)
    return None


def get_firefox_cookie(path='', host='softwarefactory'):
    """Fetch the auth cookie stored by Firefox at %path% for the
    %host% instance of Software Factory."""
    jar_path = _build_path(path)
    logger.debug('looking for firefox cookies at %s' % jar_path)
    try:
        c = sqlite3.connect(jar_path)
        cur = c.cursor()
        cur.execute('select value from moz_cookies where host '
                    'like ? and name = "auth_pubtkt" '
                    'order by expiry desc', ('%' + host + '%',))
        for cookie_info in cur.fetchall():
            if cookie_info:
                if _is_cookie_valid(cookie_info[0]):
                    return cookie_info[0]
    except sqlite3.OperationalError as e:
        logger.debug("Could not read cookies: %s" % e)
    return None


def die(msg):
    logger.error(msg)
    sys.exit(1)


def split_and_strip(s):
    return [x.strip() for x in s.split(',')]


def load_rc_file(args):
    for path in DEFAULT_RC_PATHS:
        if os.path.isfile(path):
            logger.debug("Using rc file %s" % path)
            with open(path, 'r') as ymlfile:
                cfg = yaml.load(ymlfile)
            if not isinstance(cfg, dict):
                raise Exception("Incorrect rc file format")
            if args.env not in cfg:
                raise Exception("Unknown environment %s" % args.env)
            env = cfg[args.env]
            if env.get('url'):
                args.url = env['url']
            if env.get('insecure'):
                args.insecure = env['insecure']
            if env.get('debug'):
                args.debug = env['debug']
            if env.get('auth'):
                if env['auth'].get('username'):
                    args.auth = env['auth']['username']
                    # would anybody put a password but no username?
                    if env['auth'].get('password'):
                        args.auth += ':' + env['auth']['password']
                    return
                if env['auth'].get('api-key'):
                    args.api_key = env['auth']['api-key']
                    return
                if env['auth'].get('cookie'):
                    args.cookie = env['auth']['cookie']
                    return
                if env['auth'].get('github-token'):
                    args.github_token = env['auth']['github-token']
                    return
            return
        else:
            logger.debug("Could not find rc file %s" % path)
    raise Exception("Environment %s could not be loaded: "
                    "no rc file found" % args.env)


def fail_if_keycloak(args):
    """Actions that cannot be run without cauth."""
    services = sfauth.get_managesf_info(args.url)['service']['services']
    if 'keycloak' in services:
        die("This action is only available through the cauth service")


def default_arguments(parser):
    parser.add_argument('--env', '-e',
                        help='The environment to use from an RC file. '
                             'Default locations are .software-factory.rc, '
                             '~/.software-factory.rc, ~/.software-factory'
                             '/software-factory.rc and /etc/software-factory'
                             '/software-factory.rc in order of discovery')
    parser.add_argument('--url',
                        help='Software Factory public gateway URL')
    parser.add_argument('--auth', metavar='username[:password]',
                        help='Authentication information',)
    parser.add_argument('--token', metavar='JSONWebToken',
                        help='Authenticate with a Keycloak Token')
    parser.add_argument('--github-token', metavar='GithubPersonalAccessToken',
                        help='Authenticate with a Github Access Token')
    parser.add_argument('--api-key', metavar='APIKEY',
                        help='Authenticate with a SF API key')
    parser.add_argument('--auth-server-url', metavar='central-auth-server',
                        help='URL of the central auth server')
    parser.add_argument('--cookie', metavar='Authentication cookie',
                        help='cookie of the user if known')
    parser.add_argument('--insecure', default=False, action='store_true',
                        help='disable SSL certificate verification, '
                        'verification is enabled by default')
    parser.add_argument('--json', default=False, action='store_true',
                        help='Return output as JSON instead of '
                        'human readable output')
    parser.add_argument('--debug', default=False, action='store_true',
                        help='enable debug messages in console, '
                        'disabled by default')
    parser.add_argument('--gerrit-admin-key',
                        default="/root/.ssh/gerrit_admin",
                        help='path to gerrit admin ssh private key')


def user_management_command(parser):
    uc = parser.add_parser('user',
                           help='local users backend related commands')
    suc = uc.add_subparsers(dest="subcommand")

    cump = suc.add_parser('create', help='Create user. Admin rights required')
    cump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True, help='A unique username/login')
    cump.add_argument('--password', '-p', nargs='?', metavar='password',
                      required=True,
                      help='The user password, can be provided interactively'
                           ' if this option is empty')
    cump.add_argument('--email', '-e', nargs='?', metavar='email',
                      required=True, help='The user email')
    cump.add_argument('--fullname', '-f', nargs='+', metavar='John Doe',
                      help="The user's full name, defaults to username",
                      required=True)
    cump.add_argument('--ssh-key', '-s', nargs='?', metavar='/path/to/pub_key',
                      required=False, help="The user's ssh public key file")
    uump = suc.add_parser('update', help='Update user details. Admin can'
                          ' update details of all users. User can update its'
                          ' own details.')
    uump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True,
                      help='the user to update, defaults to current user')
    uump.add_argument('--password', '-p', nargs='?', metavar='password',
                      required=False, default=False,
                      help='The user password, can be provided interactively'
                           ' if this option is empty')
    uump.add_argument('--email', '-e', nargs='?', metavar='email',
                      required=False, help='The user email')
    uump.add_argument('--fullname', '-f', metavar='John Doe', nargs='+',
                      required=False, help="The user's full name")
    uump.add_argument('--ssh-key', '-s', nargs='?', metavar='/path/to/pub_key',
                      required=False, help="The user's ssh public key file")
    dump = suc.add_parser('delete', help='Delete user. Admin rights required')
    dump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True, help='the user to delete')


def sf_user_management_command(parser):
    sfu = parser.add_parser('sf_user',
                            help='manage registered users on Software Factory')
    sfu_sub = sfu.add_subparsers(dest='subcommand')
    create = sfu_sub.add_parser('create', help='register a user on SF')
    create.add_argument('--username', '-u', nargs='?', metavar='username',
                        required=True, help='A unique username/login')
    create.add_argument('--fullname', '-f', nargs='+', metavar='John Doe',
                        required=True, help="The user's full name")
    create.add_argument('--email', '-e', nargs='?', metavar='email',
                        required=True, help="The user's email")
    create.add_argument('--ssh-key', '-s', nargs='?',
                        metavar='/path/to/pubkey',
                        required=False, help="The user's ssh public key file")
    create.add_argument('--password', '-p', nargs='?', metavar='password',
                        required=False, help="the user's password")
    sfu_sub.add_parser('list', help='list all registered users')
    delete = sfu_sub.add_parser('delete', help='de-register a user from SF')
    delete.add_argument('--username', '-u', nargs='?', metavar='username',
                        required=False, help=('the username '
                                              '(use either this or email)'))
    delete.add_argument('--email', '-e', nargs='?', metavar='email',
                        required=False, help=("the user's email (use "
                                              "either this or username)"))


def github_command(parser):
    gh = parser.add_parser('github', help='Github tools')

    sub_cmd = gh.add_subparsers(dest='subcommand')

    createrepo = sub_cmd.add_parser('create-repo')
    createrepo.add_argument(
        '--name', '-n', nargs='?', metavar='project-name', required=True)
    createrepo.add_argument(
        '--org', '-o', nargs='?', metavar='organization')

    deleterepo = sub_cmd.add_parser('delete-repo')
    deleterepo.add_argument(
        '--name', '-n', nargs='?', metavar='project-name', required=True)
    deleterepo.add_argument(
        '--org', '-o', nargs='?', metavar='organization')

    deploy_key = sub_cmd.add_parser('deploy-key')
    deploy_key.add_argument(
        '--name', '-n', nargs='?', metavar='project-name', required=True)
    deploy_key.add_argument(
        '--org', '-o', nargs='?', metavar='organization')

    deploy_key.add_argument('--keyfile', nargs='?', required=True)

    fork_repo = sub_cmd.add_parser('fork-repo')
    fork_repo.add_argument(
        '--fork', '-f', nargs='?', metavar='fork', required=True)
    fork_repo.add_argument(
        '--name', '-n', nargs='?', metavar='project-name', required=True)
    fork_repo.add_argument(
        '--org', '-o', nargs='?', metavar='organization')


def apikey_command(parser):
    gah = parser.add_parser('apikey',
                            help='API access commands')

    sub_cmd = gah.add_subparsers(dest='subcommand')

    sub_cmd.add_parser('get',
                       help='Get my personal API'
                            ' access key')
    sub_cmd.add_parser('create',
                       help='Create my personal API'
                            ' access key')
    sub_cmd.add_parser('delete',
                       help='Delete my personal API'
                            ' access key')


def project_command(parser):
    project = parser.add_parser('project',
                                help='project related commands')
    proc = project.add_subparsers(dest='subcommand')
    clone = proc.add_parser('clone',
                            help="Clone project's repositories")
    clone.add_argument('--project', '-p', required=True)
    clone.add_argument('--dest-path', '-d', required=True)


def command_options(parser):
    sp = parser.add_subparsers(dest="command")
    user_management_command(sp)
    sf_user_management_command(sp)
    apikey_command(sp)
    github_command(sp)
    project_command(sp)


def get_auth_params(args):
    if args.cookie is not None:
        return {'cookies': args.cookie, 'headers': None}
    try:
        url = args.auth_server_url.rstrip('/')
        if args.auth is not None:
            (username, password) = args.auth.split(':')
            params = sfauth.get_auth_params(url, username=username,
                                            password=password,
                                            verify=(not args.insecure))
        elif args.github_token is not None:
            token = args.github_token
            params = sfauth.get_auth_params(url, github_access_token=token,
                                            verify=(not args.insecure))
        elif args.token is not None:
            token = args.token
            params = sfauth.get_auth_params(url, token=token,
                                            verify=(not args.insecure))
        elif args.api_key is not None:
            api_key = args.api_key
            params = sfauth.get_auth_params(url, api_key=api_key,
                                            verify=(not args.insecure))
        else:
            die('Please provide credentials')
        return params
    except Exception as e:
        die(e.message)


def response(resp, quiet=False):
    if resp.ok:
        if not quiet:
            content_json = \
                resp.headers.get(
                    'content-type', '').startswith("application/json")
            if content_json and JSON_OUTPUT:
                # Response is already json and we want json
                # prettyfied output so load the json string
                # from the response and dump it with indent
                # to pretty print it by keeping valid json
                print(json.dumps(resp.json(), indent=2))
            elif content_json:
                # Response if json but user does not ask
                # for json output so return str of python object
                print(resp.json())
            else:
                print(resp.text)
        return True
    if resp.status_code // 100 == 4:
        if resp.status_code == 409:
            msg = 'RESOURCE CONFLICT\n%s' % resp.text
        elif resp.status_code == 401:
            msg = ('You are not authorized to perform this action. Please '
                   'contact an administrator of the platform if you believe '
                   'this should not be the case.')
            try:
                policy = re.search('Failure to comply with policy (.+)\n',
                                   resp.text).groups()[0]
            except Exception:
                policy = "UNKNOWN"
            msg += '\n\nPolicy enforced: %s' % policy
        else:
            msg = 'NOT FOUND\n%s' % resp.text
        die(msg)
    if resp.status_code // 100 == 5:
        msg = 'SERVER ERROR\n%s' % resp.text
        die(msg)
    else:
        die(resp.text)


def build_url(*args):
    return '/'.join(s.strip('/') for s in args) + '/'


def apikey_action(args, base_url):
    url = base_url + '/apikey'
    if args.command != 'apikey':
        return False

    if args.subcommand not in ['create', 'delete', 'get']:
        return False

    fail_if_keycloak(args)

    if args.subcommand == 'get':
        resp = request('get', url)
        return response(resp)

    if args.subcommand == 'create':
        resp = request('post', url)
        return response(resp)

    if args.subcommand == 'delete':
        resp = request('delete', url)
        return response(resp, quiet=True)


def github_action(args, base_url):
    if args.subcommand not in ['create-repo', 'delete-repo',
                               'deploy-key', 'fork-repo']:
        return False

    if not args.github_token:
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": "token %s" % args.github_token
    }

    if args.subcommand == 'create-repo':
        data = {"name": args.name, "private": False}

        if args.org:
            url = "https://api.github.com/orgs/%s/repos" % args.org
        else:
            url = "https://api.github.com/user/repos"
        resp = requests.post(url, headers=headers, json=data)
        if resp.status_code == requests.codes.created:
            print("Github repo %s created." % args.name)
        return response(resp, quiet=True)

    elif args.subcommand == 'fork-repo':
        parsed = urlparse(args.fork)
        if not parsed.netloc:
            logger.info("Invalid original repo url.")
            return
        owner = parsed.path.split('/')[1]
        repo = parsed.path.split('/')[2]
        url = "https://api.github.com/repos/%s/%s/forks" % (owner, repo)
        data = None
        if args.org:
            data = {'organization': args.org}
        resp1 = requests.post(url, headers=headers, json=data)
        if resp1.status_code == requests.codes.accepted:
            print("Github repo %s forked." % repo)
        if args.name:
            data = {'name': args.name}
            if args.org:
                owner = args.org
            else:
                owner = resp1.json()["owner"]["login"]
            url = "https://api.github.com/repos/%s/%s" % (owner, repo)
            resp2 = requests.patch(url, headers=headers, json=data)
            if resp2.status_code == requests.codes.ok:
                print("Github repo renamed from %s to %s" % (repo, args.name))
            return response(resp2, quiet=True)
        else:
            return response(resp1, quiet=True)

    elif args.subcommand == 'delete-repo':
        if args.org:
            owner = args.org
        else:
            url = "https://api.github.com/user"
            resp = requests.get(url, headers=headers)
            owner = resp.json().get('login')

        url = "https://api.github.com/repos/%s/%s" % (owner, args.name)

        resp = requests.delete(url, headers=headers)
        if resp.status_code == requests.codes.no_content:
            print("Github repo %s deleted." % args.name)
        return response(resp)

    elif args.subcommand == "deploy-key":
        if args.keyfile:
            if args.org:
                owner = args.org
            else:
                url = "https://api.github.com/user"
                resp = requests.get(url, headers=headers)
                owner = resp.json().get('login')

            with open(args.keyfile, 'r') as f:
                sshkey = f.read()

            data = {
                "title": "%s ssh key" % owner,
                "key": sshkey,
                "read_only": False}

            url = "https://api.github.com/repos/%s/%s/keys" % (
                owner, args.name)
            resp = requests.post(url, headers=headers, json=data)

            if resp.status_code == requests.codes.created:
                print("SSH deploy key %s added to Github repo %s." % (
                    args.keyfile, args.name))
            return response(resp, quiet=True)

    return False


def user_management_action(args, base_url):
    if args.command != 'user':
        return False
    if args.subcommand not in ['create', 'update', 'delete']:
        return False
    services = sfauth.get_managesf_info(
        args.url,
        not args.insecure)['service']['services']
    if 'keycloak' in services:
        return keycloak_user_management_action(args, base_url)
    else:
        return cauth_user_management_action(args, base_url)


def keycloak_user_management_action(args, base_url):
    base = args.url.rstrip('/')
    url = base + '/auth/admin/realms/sf/users'
    if args.subcommand == 'create':
        password = None
        if args.password is None:
            if not getattr(args, 'email'):
                die("email required if no password is provided.")
            print("An email will be sent to %s "
                  "to set the user's password." % args.email)
        elif args.password:
            password = args.password
        userInfo = {"username": args.username,
                    "enabled": True}
        if getattr(args, 'email'):
            userInfo['email'] = args.email
        if getattr(args, 'fullname'):
            userInfo['firstName'] = args.fullname[0]
            if len(args.fullname) > 1:
                userInfo['lastName'] = args.fullname[1]
        if password is not None:
            userInfo['credentials'] = [{"type": "password",
                                        "value": password}]
        resp = request('post', url, json=userInfo)
        if resp.ok:
            if getattr(args, 'ssh_key'):
                kc_user = request('get',
                                  url + ('?username=%s' % args.username))
                userInfo = kc_user.json()[0]
                with open(args.ssh_key, 'r') as f:
                    userInfo['attributes'] = {"publicKey": [f.read()]}
                resp = request('put', url + "/" + userInfo["id"],
                               json=userInfo)
            # send an email to the user to complete registration
            if password is None:
                action_url = url + "/%s/execute-action-emails" % userInfo['id']
                action_resp = request('put', action_url,
                                      json=["UPDATE_PASSWORD",
                                            "UPDATE_PROFILE"])
                if not action_resp.ok:
                    print(action_resp.text)
            print("Provisioning services ...")
        else:
            die('Could not create user "%s": "%s"' (args.username, resp.text))
    elif args.subcommand == 'delete':
        resp = request('get',
                       url + ('?username=%s' % args.username))
        if resp.ok:
            kc_users = resp.json()
            if len(kc_users) != 1:
                die('%i user(s) found as username "%s"' % (len(kc_users),
                                                           args.username))
            user_id = kc_users[0]['id']
            del_resp = request('delete', url + "/" + user_id)
            if del_resp.ok:
                print("Deleting in services ...")
            else:
                die('Error deleting user "%s": %s' % (args.username,
                                                      del_resp.text))
        else:
            die("Error during user lookup: %s" % resp.text)
    else:
        resp = request('get',
                       url + ('?username=%s' % args.username))
        if resp.ok:
            kc_users = resp.json()
            if len(kc_users) != 1:
                die('%i user(s) found as username "%s"' % (len(kc_users),
                                                           args.username))
            userInfo = kc_users[0]
            user_id = userInfo['id']
            if getattr(args, 'email'):
                userInfo['email'] = args.email
            if getattr(args, 'fullname'):
                userInfo['firstName'] = args.fullname[0]
                if len(args.fullname) > 1:
                    userInfo['lastName'] = args.fullname[1]
            password = getattr(args, 'password')
            if password is not None:
                userInfo['credentials'] = [{"type": "password",
                                            "value": password}]
            if getattr(args, 'ssh_key'):
                with open(args.ssh_key, 'r') as f:
                    userInfo['attributes'] = {"publicKey": [f.read()]}
            update_resp = request('put', url + "/" + user_id, json=userInfo)
            if update_resp.ok:
                print("Updating in services ...")
            else:
                die('Updating user "%s" failed: %s' % (args.username,
                                                       update_resp.text))
        else:
            die("Error during user lookup: %s" % resp.text)
    keycloak_services_users_management_action(args, base_url)
    return response(resp)


def cauth_user_management_action(args, base_url):
    url = build_url(base_url, 'user', args.username)
    if args.subcommand in ['create', 'update']:
        password = None
        if args.password is None:
            # -p option has been passed by with no value
            password = getpass.getpass("Enter password: ")
        elif args.password:
            password = args.password
        info = {}
        if getattr(args, 'email'):
            info['email'] = args.email
        if getattr(args, 'ssh_key'):
            with open(args.ssh_key, 'r') as f:
                info['sshkey'] = f.read()
        if getattr(args, 'fullname'):
            info['fullname'] = ' '.join(args.fullname)
        if password:
            info['password'] = password
        resp = request('post', url, json=info)
        if args.subcommand == 'create' and resp.ok and not JSON_OUTPUT:
            pt = PrettyTable(["Username", "Fullname", "Email"])
            i = resp.json()
            if i is True:
                print("User updated")
                return True
            pt.add_row(
                [i['username'], i['fullname'], i['email']])
            print(pt)
            return True
    if args.subcommand == 'delete':
        resp = request('delete', url)
    return response(resp)


def project_action(args, base_url):
    if args.command != 'project':
        return False
    if args.subcommand not in ['clone']:
        return False
    url = build_url(base_url, 'resources')
    resources = request('get', url).json()['resources']['projects']
    if args.subcommand == 'clone':
        if args.project not in resources.keys():
            print("Requested project %s cannot be found" % args.project)
            return False
        path = os.path.expanduser(args.dest_path)
        if not os.path.isdir(path):
            print("Creating %s" % path)
            os.mkdir(path)
        for repo in resources[args.project]['source-repositories']:
            c_uri = build_url(base_url.replace('manage', 'r'),
                              repo).rstrip('/')
            print("Fetching %s in %s ..." % (
                repo, os.path.join(path, repo)))
            if os.path.isdir(os.path.join(path, repo, '.git')):
                # Already exist just fetch the refs
                light_update = True
            else:
                light_update = False
            repo = git.Repo.init(os.path.join(path, repo))
            try:
                origin = repo.remote('origin')
            except ValueError:
                origin = repo.create_remote('origin', c_uri)
            output = repo.git.remote("show", "origin").splitlines()
            head = [l.split(':')[-1].strip() for l in output if
                    re.match(r"^\s+HEAD branch: .+$", l)][0]
            repo.git.config("http.sslVerify", "%s" % (not args.insecure))
            origin.fetch(head)
            if not light_update:
                print("Checkout %s ..." % head)
                origin.pull(head)
            repo.git.branch(head, set_upstream_to="origin/%s" % head)
    return True


def cauth_services_users_management_action(args, base_url):
    url = build_url(base_url, 'services_users')
    if args.subcommand in ['create', 'delete']:
        info = {}
        if getattr(args, 'email', None):
            info['email'] = args.email
        if getattr(args, 'username', None):
            info['username'] = args.username
        if getattr(args, 'fullname', None):
            info['full_name'] = ' '.join(args.fullname)
    if args.subcommand == 'create':
        resp = request('post', url, json=info)
    elif args.subcommand == 'delete':
        resp = request('delete', url, json=info)
    elif args.subcommand == 'list':
        resp = request('get', url)
        if resp.ok and not JSON_OUTPUT:
            pt = PrettyTable(["Id", "Username", "Fullname", "Email",
                              "Cauth_id"])
            for i in resp.json():
                pt.add_row(
                    [i['id'], i['username'], i['fullname'], i['email'],
                     i['cauth_id']])
            print(pt)
            return True
        else:
            return response(resp)
    return response(resp)


def keycloak_services_users_management_action(args, base_url):
    if args.subcommand in ['create', 'update']:
        print("Provisioning gerrit ...")
        cmd = "ssh admin@gerrit -p 29418 -i %s gerrit create-account "
        cmd = cmd % args.gerrit_admin_key
        if getattr(args, 'fullname'):
            cmd += " --full-name \"'%s'\"" % ' '.join(args.fullname)
        if getattr(args, 'email'):
            cmd += " --email %s" % args.email
        if getattr(args, 'password'):
            cmd += " --http-password %s" % args.password
        if getattr(args, 'username'):
            cmd += " %s" % args.username
    else:
        print("Deactivating user in gerrit ...")
        cmd = "ssh admin@gerrit -p 29418 -i %s gerrit set-account --inactive "
        cmd = cmd % args.gerrit_admin_key
        cmd += args.username
    try:
        env = os.environ.copy()
        env['LC_ALL'] = 'en_US.UTF-8'
        output = subprocess.check_output(
            shlex.split(cmd), stderr=subprocess.STDOUT,
            env=env).decode('utf-8')
    except subprocess.CalledProcessError as err:
        if err.output:
            die('Command "%s" failed with the following '
                'error message: "%s"' % (cmd, err.output))
        else:
            die("Error with user management in gerrit: %s" % err)
    print(output)
    return True


def services_users_management_action(args, base_url):
    if args.command != 'sf_user':
        return False
    if args.subcommand not in ['create', 'list', 'delete']:
        return False
    services = sfauth.get_managesf_info(
        args.url,
        not args.insecure)['service']['services']
    if 'keycloak' in services:
        return keycloak_services_users_management_action(args, base_url)
    else:
        return cauth_services_users_management_action(args, base_url)


def main():
    parser = argparse.ArgumentParser(
        description="Software Factory CLI")
    default_arguments(parser)
    command_options(parser)
    args = parser.parse_args()
    if args.env:
        try:
            load_rc_file(args)
        except Exception as e:
            die(e.message)
    fmt = '\033[1;33m%(levelname)-5.5s [%(name)s] %(message)s\033[1;0m'
    if args.debug:
        logging.basicConfig(format=fmt, level=logging.DEBUG)
    else:
        logging.basicConfig(format=fmt, level=logging.INFO)

    globals()['JSON_OUTPUT'] = args.json
    globals()['VERIFY_SSL'] = not args.insecure

    # Set local url and auth if sfconfig.yaml is present
    sfconfig = None
    if os.path.isfile("/etc/software-factory/sfconfig.yaml"):
        sfconfig = yaml.load(open("/etc/software-factory/sfconfig.yaml"))
    if not args.url and sfconfig:
        args.url = "https://%s" % sfconfig["fqdn"]
    if not args.auth and sfconfig:
        args.auth = "admin:%s" % sfconfig["authentication"]["admin_password"]

    if not args.url:
        base_url = ""
        if args.command != "github":
            parser.error('argument --url is required')
    if args.url and not args.url.lower().startswith('http'):
        parser.error('missing protocol in argument --url: %s' % args.url)
    else:
        if args.command != "github":
            base_url = "%s/manage" % args.url.rstrip('/')
        if args.command == "apikey":
            base_url = "%s/auth" % args.url.rstrip('/')

    if args.auth_server_url is None:
        args.auth_server_url = args.url

    # check that the cookie is still valid
    if args.cookie is not None:
        if not _is_cookie_valid(args.cookie):
            die("Invalid cookie")

    if (args.auth is None and
       args.cookie is None and
       args.github_token is None and
       args.api_key is None and
       not (args.command == 'project' and args.subcommand == 'clone')):
        host = urlparse(args.url).hostname
        logger.info("No authentication provided, looking for an existing "
                    "cookie for host %s... " % host),
        # try Chrome
        CHROME_COOKIES_PATH = _build_path('.config/chromium/Default/Cookies')
        cookie = get_chromium_cookie(CHROME_COOKIES_PATH,
                                     host)
        if _is_cookie_valid(cookie):
            args.cookie = cookie
        if args.cookie is None:
            # try Firefox
            FIREFOX_COOKIES_PATH = _build_path(
                '.mozilla/firefox/*.default/cookies.sqlite')
            paths = glob.glob(FIREFOX_COOKIES_PATH)
            # FF can have several profiles, let's cycle through
            # them until we find a cookie
            for p in paths:
                cookie = get_firefox_cookie(p, host)
                if _is_cookie_valid(cookie):
                    args.cookie = cookie
                    break
        if args.cookie is None:
            logger.error("No cookie found.")
            die("Please provide valid credentials.")
        userid = args.cookie.split('%3B')[0].split('%3D')[1]
        logger.info("Authenticating as %s" % userid)

    if args.auth is not None and ":" not in args.auth:
        password = getpass.getpass("%s's password: " % args.auth)
        args.auth = "%s:%s" % (args.auth, password)

    if args.command != "github" and not (
            args.command == 'project' and args.subcommand == 'clone'):
        globals()['REQUESTS_PARAMS'] = get_auth_params(args)

    if args.insecure:
        import urllib3
        urllib3.disable_warnings()

    if not(apikey_action(args, base_url) or
           user_management_action(args, base_url) or
           github_action(args, base_url) or
           services_users_management_action(args, base_url) or
           project_action(args, base_url)):
        die("ManageSF failed to execute your command")


if __name__ == '__main__':
    main()
