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

import json
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import requests

import logging
import sys

logger = logging.getLogger('sfmanager')
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


class IntrospectionNotAvailableError(Exception):
    pass


def get_jwt(remote_gateway, username, password):
    if 'keycloak' not in remote_gateway:
        # assumption, might backfire
        if not remote_gateway.startswith('https://'):
            wk_root = 'https://' + remote_gateway
    else:
        wk_root = remote_gateway
    wk_url = "%s/auth/realms/sf/.well-known/openid-configuration"
    wk = requests.get(wk_url % wk_root, verify=True).json()
    token_endpoint = wk.get('token_endpoint')
    if token_endpoint is None:
        raise Exception('No Token Endpoint defined at %s' % (wk_url % wk_root))
    data = {
        'username': username,
        'password': password,
        'grant_type': 'password',
        'client_id': 'managesf',
    }
    token_request = requests.post(token_endpoint, data, verify=True)
    if (int(token_request.status_code) >= 400 and
       int(token_request.status_code) < 500):
        raise Exception('Incorrect username/password combination')
    elif int(token_request.status_code) >= 500:
        raise Exception('Server failure: %s' % token_request.text)
    else:
        jwt = token_request.json()['access_token']
    return {
      'headers': {
          'Authorization': 'bearer %s' % jwt
                  }
            }


def get_cookie(auth_server,
               username=None, password=None,
               github_access_token=None,
               api_key=None,
               use_ssl=True,
               verify=True):
    # TODO: remove this parameter once
    #       I8df68b7f74344371e4b45b4a6d1cc3362b70b61e is merged
    if use_ssl is False:
        use_ssl = True
    if urlparse(auth_server).scheme == '':
        auth_server = "https://%s" % auth_server
    cauth_info = get_cauth_info(auth_server, verify)
    url = "%s/auth/login" % auth_server
    auth_params = {'back': '/',
                   'args': {}, }
    methods = cauth_info['service']['auth_methods']
    if (username and password and ('Password' in methods)):
        auth_params['args'] = {'username': username,
                               'password': password}
        auth_params['method'] = 'Password'
    elif (github_access_token and
          ('GithubPersonalAccessToken' in methods)):
        auth_params['args'] = {'token': github_access_token}
        auth_params['method'] = 'GithubPersonalAccessToken'
    elif (api_key and ('APIKey' in methods)):
        auth_params['args'] = {'api_key': api_key}
        auth_params['method'] = 'APIKey'
    else:
        m = "Missing credentials (accepted auth methods: %s)"
        methods = ','.join(methods)
        raise ValueError(m % methods)
    header = {'Content-Type': 'application/json'}
    resp = requests.post(url, json.dumps(auth_params, sort_keys=True),
                         allow_redirects=False,
                         verify=verify,
                         headers=header)
    return resp.cookies.get('auth_pubtkt', '')


def _get_service_info(url, verify=True):
    resp = requests.get(url, allow_redirects=False,
                        verify=verify)
    if resp.status_code > 399:
        raise IntrospectionNotAvailableError()
    return resp.json()


def get_cauth_info(auth_server, verify=True):
    url = "%s/auth/about/" % auth_server
    return _get_service_info(url, verify)


def get_managesf_info(server, verify=True):
    url = "%s/about/" % server
    return _get_service_info(url, verify)


def get_auth_params(server,
                    username=None, password=None,
                    github_access_token=None,
                    token=None,
                    api_key=None,
                    use_ssl=True,
                    verify=True):
    try:
        services = get_managesf_info(server)['service']['services']
    except IntrospectionNotAvailableError:
        logger.info(
            'Introspection not available, assuming cookie authentication')
        services = ['cauth', ]
    params = {'cookies': None,
              'headers': None}
    if 'keycloak' in services:
        if token is not None:
            extras = {
              'headers': {
                  'Authorization': 'bearer %s' % token
                          }
                    }
        else:
            extras = get_jwt(server, username, password)
    else:
        cookie = get_cookie(server, username, password,
                            github_access_token, api_key, use_ssl,
                            verify)
        extras = {
            'cookies': cookie,
        }
    params.update(**extras)
    return params
