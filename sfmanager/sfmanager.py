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
import base64
import getpass
import glob
import json
import logging
import os
import re
import requests
import sqlite3
import sys
import time
import urlparse
import urllib
import yaml
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from prettytable import PrettyTable


try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

from pysflib import sfauth

JSON_OUTPUT = False

requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


logger = logging.getLogger('sfmanager')
ch = logging.StreamHandler()
fh_debug = logging.FileHandler('sfmanager.log')
fh_debug.setLevel(logging.DEBUG)
info_formatter = '%(levelname)-8s - %(message)s'
debug_formatter = '%(asctime)s - %(name)-16s - ' + info_formatter
info_formatter = logging.Formatter(info_formatter)
debug_formatter = logging.Formatter(debug_formatter)
fh_debug.setFormatter(debug_formatter)


logger.addHandler(ch)
logger.addHandler(fh_debug)
requests_log.addHandler(fh_debug)


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
    l = s.split(',')
    return [x.strip() for x in l]


def default_arguments(parser):
    parser.add_argument('--url',
                        help='Software Factory public gateway URL')
    parser.add_argument('--auth', metavar='username[:password]',
                        help='Authentication information')
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


def membership_command(parser):
    def membership_args(x):
        x.add_argument('--project', metavar='project-name', required=True,
                       help='The project name')
        x.add_argument('--user', metavar='user@example.com', required=True,
                       help="The user's email registered in Software Factory")

    root = parser.add_parser('membership',
                             help='Project memberships commands')
    sub_cmd = root.add_subparsers(dest='subcommand')
    add = sub_cmd.add_parser('add', help="Add a user to a project's group(s)")
    membership_args(add)
    add.add_argument('--groups', nargs='+',
                     metavar='[core-group|dev-group|ptl-group]',
                     required=True,
                     help="The project's group(s)",
                     choices=['core-group', 'dev-group', 'ptl-group'])

    remove = sub_cmd.add_parser('remove',
                                help="Remove a user from project's group")
    membership_args(remove)
    remove.add_argument('--group', metavar='[core-group|dev-group|ptl-group]',
                        help="The project's group(s)",
                        choices=['core-group', 'dev-group', 'ptl-group'])


def system_command(parser):
    root = parser.add_parser('system', help='system level commands')
    sub_cmd = root.add_subparsers(dest='subcommand')
    sub_cmd.add_parser('backup_start',
                       help='Start the backup process in Software Factory')
    sub_cmd.add_parser('backup_get',
                       help='Download the latest backup from Software Factory')
    restore = sub_cmd.add_parser('restore',
                                 help='Restore Software Factory data')
    restore.add_argument('--filename', metavar='absolute-path',
                         required=True,
                         help='The file downloaded from backup_get')


def user_management_command(parser):
    uc = parser.add_parser('user',
                           help='project users-related commands')
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
    sfu_sub.add_parser('list', help='list all registered users')
    delete = sfu_sub.add_parser('delete', help='de-register a user from SF')
    delete.add_argument('--username', '-u', nargs='?', metavar='username',
                        required=False, help=('the username '
                                              '(use either this or email)'))
    delete.add_argument('--email', '-e', nargs='?', metavar='email',
                        required=False, help=("the user's email (use "
                                              "either this or username)"))


def group_management_command(parser):
    g = parser.add_parser('group',
                          help='Manage standalone groups')
    g_sub = g.add_subparsers(dest='subcommand')
    create = g_sub.add_parser('create', help='create a group on SF')
    create.add_argument('--name', '-n', metavar='groupname',
                        required=True, help="A unique group's name")
    create.add_argument('--description', '-d', metavar='My group desc',
                        required=True, help="The group's description")
    glist = g_sub.add_parser('list', help="list all standalone groups"
                                          " or group' members")
    glist.add_argument('--name', '-n', help='group name to list members',
                       required=False, default=None)
    delete = g_sub.add_parser('delete', help='delete a group from SF')
    delete.add_argument('--name', '-n', metavar='groupname',
                        required=True, help="the group's name")
    add = g_sub.add_parser('add', help='Add members to a group')
    add.add_argument('--name', '-n', metavar='groupname',
                     required=True, help="the group's name")
    add.add_argument('--email', '-e', nargs='*', metavar='user1@sftests.com',
                     required=True, help="user's email(s) to include")
    remove = g_sub.add_parser('remove', help='Remove members from a group')
    remove.add_argument('--name', '-n', metavar='groupname',
                        required=True, help="the group's name")
    remove.add_argument('--email', '-e', nargs='*',
                        metavar='user1@sftests.com',
                        required=True, help="user's email(s) to remove")


def pages_command(topparser):
    pages_parser = topparser.add_parser('pages', help='pages related commands')
    sub_cmds = pages_parser.add_subparsers(dest='subcommand')
    update = sub_cmds.add_parser('update',
                                 help='Set the url to the project\'s page')
    get = sub_cmds.add_parser('get',
                              help='Get the current url to the ' +
                                   'project\'s page')
    delete = sub_cmds.add_parser('delete',
                                 help='Delete the current url to the ' +
                                      'project\'s page')
    update.add_argument('--name', '-n',
                        required=True,
                        help='The project\'s name')
    update.add_argument('--dest', '-d',
                        required=True,
                        help='The page\'s url')
    delete.add_argument('--name', '-n',
                        required=True,
                        help='The project\'s name')
    get.add_argument('--name', '-n',
                     required=True,
                     help='The project\'s name')


def project_command(sp):
    pc = sp.add_parser('project',
                       help='project-related commands')
    spc = pc.add_subparsers(dest="subcommand")
    cp = spc.add_parser('create')
    cp.add_argument('--name', '-n', nargs='?', metavar='project-name',
                    required=True)
    cp.add_argument('--description', '-d', nargs='?',
                    metavar='project-description')
    cp.add_argument('--upstream', '-u', nargs='?', metavar='GIT link')
    cp.add_argument('--upstream-ssh-key', metavar='upstream-ssh-key',
                    help='SSH key for authentication against the upstream ' +
                    'repository (without a passphrase)')
    cp.add_argument('--private', action='store_true',
                    help='set if the project is private')
    cp.add_argument('--readonly', action='store_true',
                    help='set if patch merging should be disabled')
    cp.add_argument('--add-branches', action='store_true',
                    help='include all upstream git branches to the project'
                    ' repository')

    dp = spc.add_parser('delete')
    dp.add_argument('--name', '-n', nargs='?', metavar='project-name',
                    required=True)


def tests_command(parser):
    tp = parser.add_parser('tests')
    subc = tp.add_subparsers(dest='subcommand')
    init = subc.add_parser('init',
                           help='Setup the initial tests configuration for'
                           ' a given project')
    init.add_argument('--no-scripts', action='store_true',
                      help='Does not create the tests scripts in the project')
    init.add_argument('--project', '--p', metavar='project-name',
                      required=True)


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


def gerrit_api_htpassword_command(parser):
    gah = parser.add_parser('gerrit_api_htpasswd',
                            help='Gerrit API access commands')

    sub_cmd = gah.add_subparsers(dest='subcommand')

    sub_cmd.add_parser('generate_password',
                       help='Generate a personal Gerrit API'
                            ' access htpassword')
    sub_cmd.add_parser('delete_password',
                       help='Delete my personal Gerrit API'
                            ' access htpassword')


def command_options(parser):
    sp = parser.add_subparsers(dest="command")
    project_command(sp)
    user_management_command(sp)
    sf_user_management_command(sp)
    gerrit_api_htpassword_command(sp)
    membership_command(sp)
    group_management_command(sp)
    system_command(sp)
    tests_command(sp)
    pages_command(sp)
    github_command(sp)


def get_cookie(args):
    if args.cookie is not None:
        return args.cookie
    url_stripper = re.compile('http[s]?://(.+)')
    use_ssl = False
    try:
        url = args.auth_server_url.rstrip('/')
        m = url_stripper.match(url)
        if m:
            if url.lower().startswith('https'):
                use_ssl = True
            url = m.groups()[0]
        if args.auth is not None:
            (username, password) = args.auth.split(':')
            cookie = sfauth.get_cookie(url, username=username,
                                       password=password,
                                       use_ssl=use_ssl,
                                       verify=(not args.insecure))
        elif args.github_token is not None:
            token = args.github_token
            cookie = sfauth.get_cookie(url, github_access_token=token,
                                       use_ssl=use_ssl,
                                       verify=(not args.insecure))
        elif args.api_key is not None:
            api_key = args.api_key
            cookie = sfauth.get_cookie(url, api_key=api_key,
                                       use_ssl=use_ssl,
                                       verify=(not args.insecure))
        else:
            die('Please provide credentials')
        if cookie:
            return cookie
        else:
            die('Authentication failed')
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
                print json.dumps(resp.json(), indent=2)
            elif content_json:
                # Response if json but user does not ask
                # for json output so return str of python object
                print resp.json()
            else:
                print resp.text
        return True
    if resp.status_code // 100 == 4:
        if resp.status_code == 409:
            msg = 'RESOURCE CONFLICT\n%s' % resp.text
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


def membership_action(args, base_url, headers):
    if args.command != 'membership':
        return False

    if args.subcommand not in ['add', 'remove', 'list']:
        return False
    auth_cookie = {'auth_pubtkt': get_cookie(args)}

    if '/' in args.project:
        project_name = '===' + base64.urlsafe_b64encode(args.project)
    else:
        project_name = args.project
    url = build_url(base_url, 'project/membership',
                    project_name, urllib.quote_plus(args.user))
    if args.subcommand == 'add':
        logger.info('Add member %s to project %s', args.user, args.project)
        if args.groups:
            data = json.dumps({'groups': args.groups})
        resp = requests.put(url, headers=headers, data=data,
                            cookies=auth_cookie)
        return response(resp)

    if args.subcommand == 'remove':
        logger.info('Remove member %s from project %s', args.user,
                    args.project)
        if args.group:
            url = build_url(url, args.group)
        resp = requests.delete(url, headers=headers, cookies=auth_cookie)
        return response(resp)

    return False


def project_action(args, base_url, headers):
    if args.command != 'project':
        return False
    if '/' in args.name:
        name = '===' + base64.urlsafe_b64encode(args.name)
    else:
        name = args.name
    url = build_url(base_url, "project", name)
    if args.subcommand == 'create':
        if getattr(args, 'upstream_ssh_key'):
            with open(args.upstream_ssh_key) as ssh_key_file:
                args.upstream_ssh_key = ssh_key_file.read()
        substitute = {'description': 'description',
                      'upstream': 'upstream',
                      'upstream_ssh_key': 'upstream-ssh-key',
                      'private': 'private',
                      'readonly': 'readonly',
                      'add_branches': 'add-branches'}
        info = {}
        for key, word in substitute.iteritems():
            if getattr(args, key):
                info[word] = getattr(args, key)

        params = {'headers': headers,
                  'cookies': dict(auth_pubtkt=get_cookie(args))}

        if len(info.keys()):
            params['data'] = json.dumps(info)

        resp = requests.put(url, **params)

    elif args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    else:
        return False

    return response(resp)


def tests_action(args, base_url, headers):

    if args.command != 'tests':
        return False

    if getattr(args, 'subcommand') != 'init':
        return False
    url = build_url(base_url, 'tests', args.project)
    data = {}
    if args.no_scripts:
        data['project-scripts'] = False
    else:
        data['project-scripts'] = True

    resp = requests.put(url, data=json.dumps(data), headers=headers,
                        cookies=dict(auth_pubtkt=get_cookie(args)))
    return response(resp)


def pages_action(args, base_url, headers):
    if args.command != 'pages':
        return False

    if getattr(args, 'subcommand') not in ('update', 'delete', 'get'):
        return False
    url = build_url(base_url, 'pages', args.name)
    data = {}
    if args.subcommand == 'update':
        data['url'] = args.dest
        resp = requests.post(url, data=json.dumps(data), headers=headers,
                             cookies=dict(auth_pubtkt=get_cookie(args)))
    if args.subcommand == 'get':
        resp = requests.get(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
    if args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    return response(resp)


def backup_action(args, base_url, headers):
    if args.command != 'system':
        return False

    url = build_url(base_url, 'backup')
    params = {'headers': headers,
              'cookies': dict(auth_pubtkt=get_cookie(args))}
    if args.subcommand == 'backup_get':
        resp = requests.get(url, **params)
        if resp.status_code != 200:
            die("backup_get failed with status_code " + str(resp.status_code))
        chunk_size = 1024
        with open('sf_backup.tar.gz', 'wb') as fd:
            for chunk in resp.iter_content(chunk_size):
                fd.write(chunk)
        return True

    elif args.subcommand == 'backup_start':
        resp = requests.post(url, **params)
        return response(resp)

    elif args.subcommand == 'restore':
        url = build_url(base_url, 'restore')
        filename = args.filename
        if not os.path.isfile(filename):
            die("file %s does not exist" % filename)
        files = {'file': open(filename, 'rb')}
        resp = requests.post(url, headers=headers, files=files,
                             cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp)

    return False


def gerrit_api_htpasswd_action(args, base_url, headers):
    url = base_url + '/htpasswd'
    if args.command != 'gerrit_api_htpasswd':
        return False

    if args.subcommand not in ['generate_password', 'delete_password']:
        return False

    if args.subcommand == 'generate_password':
        resp = requests.put(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp)

    elif args.subcommand == 'delete_password':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp, quiet=True)


def github_action(args, base_url, headers):
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
        data = json.dumps({"name": args.name, "private": False})

        if args.org:
            url = "https://api.github.com/orgs/%s/repos" % args.org
        else:
            url = "https://api.github.com/user/repos"
        resp = requests.post(url, headers=headers, data=data)
        if resp.status_code == requests.codes.created:
            print "Github repo %s created." % args.name
        return response(resp, quiet=True)

    elif args.subcommand == 'fork-repo':
        parsed = urlparse.urlparse(args.fork)
        if not parsed.netloc:
            logger.info("Invalid original repo url.")
            return
        owner = parsed.path.split('/')[1]
        repo = parsed.path.split('/')[2]
        url = "https://api.github.com/repos/%s/%s/forks" % (owner, repo)
        data = None
        if args.org:
            data = {'organization': args.org}
        data = json.dumps(data)
        resp1 = requests.post(url, headers=headers, data=data)
        if resp1.status_code == requests.codes.accepted:
            print "Github repo %s forked." % repo
        if args.name:
            data = json.dumps({'name': args.name})
            if args.org:
                owner = args.org
            else:
                owner = resp1.json()["owner"]["login"]
            url = "https://api.github.com/repos/%s/%s" % (owner, repo)
            resp2 = requests.patch(url, headers=headers, data=data)
            if resp2.status_code == requests.codes.ok:
                print "Github repo renamed from %s to %s" % (repo, args.name)
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
            print "Github repo %s deleted." % args.name
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

            data = json.dumps(
                {"title": "%s ssh key" % owner,
                 "key": sshkey, "read_only": False}
            )

            url = "https://api.github.com/repos/%s/%s/keys" % (
                owner, args.name)
            resp = requests.post(url, headers=headers, data=data)

            if resp.status_code == requests.codes.created:
                print "SSH deploy key %s added to Github repo %s." % (
                    args.keyfile, args.name)
            return response(resp, quiet=True)

    return False


def user_management_action(args, base_url, headers):
    if args.command != 'user':
        return False
    if args.subcommand not in ['create', 'update', 'delete']:
        return False
    url = build_url(base_url, 'user', args.username)
    if args.subcommand in ['create', 'update']:
        headers['Content-Type'] = 'application/json'
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
        resp = requests.post(url, headers=headers, data=json.dumps(info),
                             cookies=dict(auth_pubtkt=get_cookie(args)))
        if args.subcommand == 'create' and resp.ok and not JSON_OUTPUT:
            pt = PrettyTable(["Username", "Fullname", "Email"])
            i = resp.json()
            pt.add_row(
                [i['username'], i['fullname'], i['email']])
            print pt
            return True
    if args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    return response(resp)


def services_users_management_action(args, base_url, headers):
    if args.command != 'sf_user':
        return False
    if args.subcommand not in ['create', 'list', 'delete']:
        return False
    url = build_url(base_url, 'services_users')
    if args.subcommand in ['create', 'delete']:
        headers['Content-Type'] = 'application/json'
        info = {}
        if getattr(args, 'email', None):
            info['email'] = args.email
        if getattr(args, 'username', None):
                info['username'] = args.username
        if getattr(args, 'fullname', None):
            info['full_name'] = ' '.join(args.fullname)
    if args.subcommand == 'create':
        resp = requests.post(url, headers=headers, data=json.dumps(info),
                             cookies=dict(auth_pubtkt=get_cookie(args)))
    elif args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers, data=json.dumps(info),
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    elif args.subcommand == 'list':
        resp = requests.get(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
        if resp.ok and not JSON_OUTPUT:
            pt = PrettyTable(["Id", "Username", "Fullname", "Email",
                              "Cauth_id"])
            for i in resp.json():
                pt.add_row(
                    [i['id'], i['username'], i['fullname'], i['email'],
                     i['cauth_id']])
            print pt
            return True
        else:
            return response(resp)
    return response(resp)


def groups_management_action(args, base_url, headers):
    if args.command != 'group':
        return False
    if args.subcommand not in ['create', 'list', 'delete', 'remove', 'add']:
        return False
    if args.subcommand == 'list':
        if not args.name:
            url = build_url(base_url, 'group')
        else:
            url = build_url(base_url, 'group', args.name)
        resp = requests.get(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
        if resp.ok and not JSON_OUTPUT:
            if not args.name:
                pt = PrettyTable(["Group name", "Description", "Users"])
                for k, v in resp.json().items():
                    pt.add_row(
                        [k, v['description'],
                         ", ".join([user['name'] for user in v['members']])])
            else:
                pt = PrettyTable(["Username", "Name", "Email"])
                for v in resp.json().values()[0]:
                    pt.add_row([v['username'], v['name'], v['email']])
            print pt
            return True
        else:
            return response(resp)
    if args.subcommand == 'create':
        url = build_url(base_url, 'group', urllib.quote_plus(args.name))
        data = json.dumps({'description': args.description})
        resp = requests.put(url, data=data, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp, quiet=True)
    if args.subcommand == 'delete':
        url = build_url(base_url, 'group', urllib.quote_plus(args.name))
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp, quiet=True)
    if args.subcommand in ['add', 'remove']:
        url = build_url(base_url, 'group', urllib.quote_plus(args.name))
        resp = requests.get(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))
        if resp.ok:
            emails = set([v['email'] for v in resp.json().values()[0]])
            if args.subcommand == 'add':
                new = set(args.email).union(emails)
            else:
                new = set(emails).difference(args.email)
            data = json.dumps({'members': list(new)})
            resp = requests.post(url, data=data, headers=headers,
                                 cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp, quiet=True)


def main():
    parser = argparse.ArgumentParser(
        description="Software Factory CLI")
    default_arguments(parser)
    command_options(parser)
    args = parser.parse_args()
    globals()['JSON_OUTPUT'] = args.json

    # Set local url and auth if sfconfig.yaml is present
    sfconfig = None
    if os.path.isfile("/etc/puppet/hiera/sf/sfconfig.yaml"):
        sfconfig = yaml.load(open("/etc/puppet/hiera/sf/sfconfig.yaml"))
    if not args.url and sfconfig:
        args.url = "http://%s" % sfconfig["fqdn"]
    if not args.auth and sfconfig:
        args.auth = "admin:%s" % sfconfig["authentication"]["admin_password"]

    if not args.url:
        base_url = ""
        if args.command != "github":
            parser.error('argument --url is required')
    if args.url and not args.url.lower().startswith('http'):
            parser.error('missing protocol in argument --url: %s' % args.url)
    else:
        base_url = "%s/manage" % args.url.rstrip('/')

    if not args.debug:
        ch.setLevel(logging.ERROR)
        ch.setFormatter(info_formatter)
    else:
        http_client.HTTPConnection.debuglevel = 1
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(debug_formatter)

    if args.auth_server_url is None:
        args.auth_server_url = args.url

    # check that the cookie is still valid
    if args.cookie is not None:
        if not _is_cookie_valid(args.cookie):
            die("Invalid cookie")

    if (args.auth is None and
       args.cookie is None and
       args.github_token is None and
       args.api_key is None):
        host = urlparse.urlsplit(args.url).hostname
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

    headers = {}
    if args.auth is not None and ":" not in args.auth:
        password = getpass.getpass("%s's password: " % args.auth)
        args.auth = "%s:%s" % (args.auth, password)
        headers = {'Authorization': 'Basic ' + base64.b64encode(args.auth)}

    if args.insecure:
        import urllib3
        urllib3.disable_warnings()
    if not(project_action(args, base_url, headers) or
           backup_action(args, base_url, headers) or
           gerrit_api_htpasswd_action(args, base_url, headers) or
           user_management_action(args, base_url, headers) or
           membership_action(args, base_url, headers) or
           tests_action(args, base_url, headers) or
           pages_action(args, base_url, headers) or
           github_action(args, base_url, headers) or
           services_users_management_action(args, base_url, headers) or
           groups_management_action(args, base_url, headers)):
        die("ManageSF failed to execute your command")

if __name__ == '__main__':
    main()
