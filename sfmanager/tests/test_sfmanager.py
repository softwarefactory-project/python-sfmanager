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
import os
import yaml
from mock import patch
from tempfile import mkstemp, NamedTemporaryFile
from unittest import TestCase

from sfmanager import sfmanager


class FakeResponse(object):
    def __init__(self, status_code=200, text='fake', json_data=None):
        self.status_code = status_code
        self.headers = {}
        self.text = text
        self.ok = True
        self.json = lambda: json_data


class TestRCFile(TestCase):
    def setUp(self):
        _, self.rc = mkstemp()
        sfmanager.DEFAULT_RC_PATHS = [self.rc, ] + sfmanager.DEFAULT_RC_PATHS
        self.parser = argparse.ArgumentParser(description="test")
        sfmanager.default_arguments(self.parser)
        sfmanager.command_options(self.parser)

    def test_rc_file_not_found(self):
        d = sfmanager.DEFAULT_RC_PATHS
        sfmanager.DEFAULT_RC_PATHS = []
        args = self.parser.parse_args(['--env', 'sf', 'sf_user', 'list'])
        self.assertIsNotNone(args.env)
        self.assertRaisesRegexp(Exception, 'no rc file found',
                                sfmanager.load_rc_file, args)
        sfmanager.DEFAULT_RC_PATHS = d

    def test_rc_file_bad_format(self):
        with open(self.rc, 'w') as rc:
            rc.write('trololo')
        args = self.parser.parse_args(['--env', 'sf', 'sf_user', 'list'])
        self.assertIsNotNone(args.env)
        self.assertRaisesRegexp(Exception, 'Incorrect rc file format',
                                sfmanager.load_rc_file, args)

    def test_rc_file_env_not_found(self):
        with open(self.rc, 'w') as rc:
            yaml.dump({'sf': {'url': 'http://a',
                              'insecure': True,
                              'debug': True,
                              'auth': {'username': 'b',
                                       'password': 'c'}
                              }
                       }, rc, default_flow_style=False)
        args = self.parser.parse_args(['--env', 'sf2', 'sf_user', 'list'])
        self.assertIsNotNone(args.env)
        self.assertRaisesRegexp(Exception, 'Unknown environment sf2',
                                sfmanager.load_rc_file, args)

    def test_rc_file_env(self):
        with open(self.rc, 'w') as rc:
            yaml.dump({'sf': {'url': 'http://a',
                              'insecure': True,
                              'debug': True,
                              'auth': {'username': 'b',
                                       'password': 'c'}
                              },
                       'sf2': {'url': 'http://a',
                               'insecure': True,
                               'debug': True,
                               'auth': {'username': 'b',
                                        'password': 'c'}
                               },
                       'sf3': {'url': 'http://a',
                               'insecure': True,
                               'debug': True,
                               'auth': {'api-key': 'd'}
                               },
                       }, rc, default_flow_style=False)
        args = self.parser.parse_args(['--env', 'sf2', 'sf_user', 'list'])
        self.assertIsNotNone(args.env)
        sfmanager.load_rc_file(args)
        self.assertEqual('http://a', args.url)
        self.assertEqual(True, args.insecure)
        self.assertEqual(True, args.debug)
        self.assertEqual('b:c', args.auth)
        args = self.parser.parse_args(['--env', 'sf3', 'sf_user', 'list'])
        self.assertIsNotNone(args.env)
        sfmanager.load_rc_file(args)
        self.assertEqual('d', args.api_key)

    def tearDown(self):
        sfmanager.DEFAULT_RC_PATHS = sfmanager.DEFAULT_RC_PATHS[1:]


class BaseFunctionalTest(TestCase):
    def setUp(self):
        _, self.temp_path = mkstemp()
        with open(self.temp_path, 'w') as f:
            f.write('dummy data')
        self.parser = argparse.ArgumentParser(description="test")
        sfmanager.default_arguments(self.parser)
        sfmanager.command_options(self.parser)
        self.base_url = "http://tests.dom/"
        self.headers = {'Authorization': 'Basic blipblop'}
        default_args = '--url {url} --auth titi:toto --auth-server-url {url}'
        self.default_args = default_args.format(url=self.base_url).split()
        self.cookies = {'auth_pubtkt': 'fake_cookie'}
        self.expected_gh_headers = {
            'Content-Type': 'application/json',
            'Authorization': 'token ghtoken'}

    def tearDown(self):
        pass

    def assert_secure(self, method_verb, cmd_args, action_func,
                      expected_url, expected_data=None, returned_json=None):
        with patch('sfmanager.sfmanager.get_cookie') as c:
            c.return_value = 'fake_cookie'
            with patch('sfmanager.sfmanager.request') as method:
                method.return_value = FakeResponse(json_data=returned_json)
                parsed = self.parser.parse_args(cmd_args)
                self.assertTrue(action_func(parsed, self.base_url),
                                [action_func.__name__, parsed, self.base_url])

                if expected_data is not None:
                    method.assert_called_with(method_verb, expected_url,
                                              json=expected_data)
                else:
                    method.assert_called_with(method_verb, expected_url)


class TestJobsActions(BaseFunctionalTest):
    def test_list_jobs(self):
        args = self.default_args
        args += 'job list --job-name toto'.split()
        expected_url = self.base_url + 'jobs/toto/'
        returned_json = {'jenkins': [{'job_name': 'toto',
                                      'job_id': 4,
                                      'status': 'SUCCESS'}, ]}
        self.assert_secure('get', args,
                           sfmanager.job_action, expected_url,
                           returned_json=returned_json)

    def test_logs(self):
        args = self.default_args
        args += 'job logs --job-name toto --id 4'.split()
        expected_url = self.base_url + 'jobs/toto/id/4/logs/'
        returned_json = {'jenkins': {'job_name': 'toto',
                                     'job_id': 4,
                                     'logs_url': 'aaaa'}}
        self.assert_secure('get', args,
                           sfmanager.job_action, expected_url,
                           returned_json=returned_json)

    def test_parameters(self):
        args = self.default_args
        args += 'job parameters --job-name toto --id 4'.split()
        expected_url = self.base_url + 'jobs/toto/id/4/parameters/'
        returned_json = {'jenkins': {'job_name': 'toto',
                                     'job_id': 4,
                                     'parameters': [{'name': 'a',
                                                     'value': 'b'}, ]}}
        self.assert_secure('get', args,
                           sfmanager.job_action, expected_url,
                           returned_json=returned_json)

    def test_run(self):
        args = self.default_args
        args += 'job run --job-name toto'.split()
        expected_url = self.base_url + 'jobs/toto/'
        self.assert_secure('post', args,
                           sfmanager.job_action, expected_url, {},
                           returned_json={'jenkins': {'job_name': 'toto',
                                                      'job_id': 2,
                                                      'status': 'PENDING'}})

    def test_stop(self):
        args = self.default_args
        args += 'job stop --job-name toto --id 2'.split()
        expected_url = self.base_url + 'jobs/toto/id/2/'
        self.assert_secure('delete', args,
                           sfmanager.job_action, expected_url,
                           returned_json={'jenkins': {'job_name': 'toto',
                                                      'job_id': 2,
                                                      'status': 'ABORTED'}})


class TestImagesActions(BaseFunctionalTest):
    def test_list_images(self):
        args = self.default_args
        args += 'image list -p default'.split()
        expected_url = self.base_url + 'nodes/images//default/'
        keys = ['id', 'provider_name', 'image_name', 'hostname',
                'version', 'image_id',
                'server_id', 'state', 'age']
        img_info = dict(zip(keys, ['aaa'] * len(keys)))
        returned_json = {'nodepool': [img_info, ]}
        self.assert_secure('get', args,
                           sfmanager.image_action, expected_url,
                           returned_json=returned_json)

    def test_update_image(self):
        args = self.default_args
        args += 'image update -p default -i sfcentos'.split()
        expected_url = self.base_url + 'nodes/images/update/sfcentos/default/'
        returned_json = {"nodepool": {"update_id": 1}}
        self.assert_secure('put', args,
                           sfmanager.image_action, expected_url,
                           returned_json=returned_json)

    def test_update_image_status(self):
        args = self.default_args
        args += 'image update-status -u 29'.split()
        expected_url = self.base_url + 'nodes/images/update/29/'
        u = {"status": "SUCCESS", "image": "sfcentos",
             "error": "", "exit_code": "0", "provider": "default",
             "output": "coolio burrito", "id": "29"}
        returned_json = {"nodepool": u}
        self.assert_secure('get', args,
                           sfmanager.image_action, expected_url,
                           returned_json=returned_json)


class TestNodesActions(BaseFunctionalTest):
    def test_list_nodes(self):
        args = self.default_args
        args += 'node list --id toto'.split()
        expected_url = self.base_url + 'nodes/id/toto/'
        keys = ['node_id', 'provider_name', 'AZ', 'label',
                'target', 'manager', 'hostname', 'node_name',
                'server_id', 'ip', 'state', 'age']
        node_info = dict(zip(keys, ['aaa'] * len(keys)))
        returned_json = {'nodepool': [node_info, ]}
        self.assert_secure('get', args,
                           sfmanager.node_action, expected_url,
                           returned_json=returned_json)

    def test_hold_node(self):
        args = self.default_args
        args += 'node hold --id toto'.split()
        expected_url = self.base_url + 'nodes/id/toto/'
        keys = ['node_id', 'provider_name', 'AZ', 'label',
                'target', 'manager', 'hostname', 'node_name',
                'server_id', 'ip', 'state', 'age']
        node_info = dict(zip(keys, ['aaa'] * len(keys)))
        returned_json = {'nodepool': [node_info, ]}
        self.assert_secure('put', args,
                           sfmanager.node_action, expected_url,
                           returned_json=returned_json)

    def test_delete_node(self):
        args = self.default_args
        args += 'node delete --id toto'.split()
        expected_url = self.base_url + 'nodes/id/toto/'
        keys = ['node_id', 'provider_name', 'AZ', 'label',
                'target', 'manager', 'hostname', 'node_name',
                'server_id', 'ip', 'state', 'age']
        node_info = dict(zip(keys, ['aaa'] * len(keys)))
        returned_json = {'nodepool': [node_info, ]}
        self.assert_secure('delete', args,
                           sfmanager.node_action, expected_url,
                           returned_json=returned_json)

    def test_add_user_key(self):
        args = self.default_args
        expected_url = self.base_url + 'nodes/id/toto/authorize_key/'
        with NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write("ssh-rsa blah")
        d = {'public_key': 'ssh-rsa blah'}
        args += ('node add-user-key --id toto --key %s' % tmpfile.name).split()
        # the operation calls POST then GET
        with patch('sfmanager.sfmanager.get_cookie') as c:
            c.return_value = 'fake_cookie'
            with patch('sfmanager.sfmanager.request') as r:
                def side_effect(*argv, **kwarg):
                    if argv[0] == 'post':
                        return FakeResponse(json_data={'nodepool': 'OK'})
                    else:
                        return FakeResponse(json_data={})
                r.side_effect = side_effect
                parsed = self.parser.parse_args(args)
                self.assertTrue(sfmanager.node_action(parsed, self.base_url))
                r.assert_any_call('post', expected_url, json=d)
        try:
            os.remove(tmpfile.name)
        except IOError:
            pass


class TestUserActions(BaseFunctionalTest):
    def test_user_create(self):
        args = self.default_args
        data = {'email': 'e@test.com',
                'password': 'abc123',
                'username': 'toto',
                'fullname': 'toto the tester'}
        cmd = 'user create -f {fullname} -u u1 -p {password} --email {email}'
        args += cmd.format(**data).split()
        expected_url = self.base_url + 'user/u1/'
        expected_data = {'email': data['email'], 'password': data['password'],
                         'fullname': data['fullname']}
        self.assert_secure('post', args, sfmanager.user_management_action,
                           expected_url, expected_data, returned_json=data)

    def test_user_delete(self):
        args = self.default_args
        args += 'user delete --user test2'.split()
        expected_url = self.base_url + 'user/test2/'
        self.assert_secure('delete', args, sfmanager.user_management_action,
                           expected_url)

    def test_user_update(self):
        args = self.default_args
        data = {'email': 'e@test.com', 'password': 'abc123'}
        cmd = 'user update --username t3 --password {password} --email {email}'
        args += cmd.format(**data).split()
        expected_url = self.base_url + 'user/t3/'
        self.assert_secure('post', args, sfmanager.user_management_action,
                           expected_url, data)

    def test_user_update_missing_username(self):
        args = self.default_args
        data = {'email': 'e@test.com', 'password': 'abc123'}
        cmd = 'user update --password'
        args += cmd.format(**data).split()
        self.assertRaises(SystemExit, self.parser.parse_args)


class TestRegisteredUserActions(BaseFunctionalTest):
    def test_user_create(self):
        args = self.default_args
        data = {'email': 'e@test.com',
                'full_name': 'toto the tester',
                'username': 'toto'}
        cmd = 'sf_user create -f {full_name} -u {username} --email {email}'
        args += cmd.format(**data).split()
        expected_url = self.base_url + 'services_users/'
        self.assert_secure('post', args,
                           sfmanager.services_users_management_action,
                           expected_url, data)

    def test_user_delete_username(self):
        args = self.default_args
        args += 'sf_user delete --username test2'.split()
        data = {'username': 'test2', }
        expected_url = self.base_url + 'services_users/'
        self.assert_secure('delete', args,
                           sfmanager.services_users_management_action,
                           expected_url, data)

    def test_user_delete_email(self):
        args = self.default_args
        args += 'sf_user delete --email test2@testy.com'.split()
        data = {'email': 'test2@testy.com', }
        expected_url = self.base_url + 'services_users/'
        self.assert_secure('delete', args,
                           sfmanager.services_users_management_action,
                           expected_url, data)

    def test_list(self):
        args = self.default_args
        args += 'sf_user list'.split()
        expected_url = self.base_url + 'services_users/'
        data = [{'username': 'joe', 'fullname': 'John Doe',
                 'email': 'joe@tests.com', 'cauth_id': '1', 'id': '1'}]
        self.assert_secure('get', args,
                           sfmanager.services_users_management_action,
                           expected_url, returned_json=data)


class TestSystemActions(BaseFunctionalTest):
    def test_backup(self):
        args = self.default_args
        args += 'system backup_start'.split()
        expected_url = self.base_url + 'backup/'
        self.assert_secure('post', args, sfmanager.backup_action, expected_url)


class TestGithubActions(BaseFunctionalTest):
    def test_create_repo(self):
        args = '--github-token ghtoken github create-repo -n reponame'.split()
        parsed_args = self.parser.parse_args(args)

        expected_url = "https://api.github.com/user/repos"
        expected_data = {"name": "reponame", "private": False}

        with patch('requests.post') as method:
            sfmanager.github_action(parsed_args, "")

            call_args, call_kwargs = method.call_args
            self.assertEqual(call_args[0], expected_url)
            self.assertEqual(call_kwargs.get('headers'),
                             self.expected_gh_headers)
            self.assertEqual(call_kwargs.get('json'),
                             expected_data)

    def test_create_org_repo(self):
        args = '--github-token ghtoken '
        args += 'github create-repo -n reponame -o orgname'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/orgs/orgname/repos"
        expected_data = {"name": "reponame", "private": False}

        with patch('requests.post') as method:
            sfmanager.github_action(parsed_args, "")

            call_args, call_kwargs = method.call_args
            self.assertEqual(call_args[0], expected_url)
            self.assertEqual(call_kwargs.get('headers'),
                             self.expected_gh_headers)
            self.assertEqual(call_kwargs.get('json'),
                             expected_data)

    def test_fork_repo(self):
        args = '--github-token ghtoken github fork-repo '
        args += '--fork https://github.com/openstack/swift '
        args += '--name swift'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/repos/openstack/swift/forks"

        with patch('requests.post') as method:
            with patch('requests.patch'):
                sfmanager.github_action(parsed_args, "")

                call_args, call_kwargs = method.call_args
                self.assertEqual(call_args[0], expected_url)
                self.assertEqual(call_kwargs.get('headers'),
                                 self.expected_gh_headers)

    def test_fork_repo_org(self):
        args = '--github-token ghtoken github fork-repo '
        args += '--fork https://github.com/openstack/swift '
        args += '--org rdo-packages '
        args += '--name swift'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/repos/openstack/swift/forks"

        with patch('requests.post') as method:
            with patch('requests.patch'):
                sfmanager.github_action(parsed_args, "")

                call_args, call_kwargs = method.call_args
                self.assertEqual(call_args[0], expected_url)
                self.assertEqual(call_kwargs.get('headers'),
                                 self.expected_gh_headers)

        expected_data = {"organization": "rdo-packages"}
        self.assertEqual(call_kwargs.get('json'), expected_data)

    @patch('requests.delete')
    @patch('requests.get')
    def test_delete_repo(self, get_method, delete_method):
        args = '--github-token ghtoken github delete-repo -n reponame'.split()
        parsed_args = self.parser.parse_args(args)

        get_method.return_value.json.return_value = {'login': 'username'}
        expected_url = "https://api.github.com/repos/username/reponame"
        kwargs = {'headers': self.expected_gh_headers}
        sfmanager.github_action(parsed_args, "")
        delete_method.assert_called_with(expected_url, **kwargs)

    @patch('requests.delete')
    @patch('requests.get')
    def test_delete_org_repo(self, get_method, delete_method):
        args = '--github-token ghtoken '
        args += 'github delete-repo -n reponame -o orgname'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/repos/orgname/reponame"
        kwargs = {'headers': self.expected_gh_headers}
        sfmanager.github_action(parsed_args, "")
        delete_method.assert_called_with(expected_url, **kwargs)

    @patch('requests.post')
    @patch('requests.get')
    def _test_deploy_key(self, orgname, get_method, post_method):
        with NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write("ssh-rsa")

        args = '--github-token ghtoken '
        args += 'github deploy-key -n reponame '
        args += '--keyfile %s ' % tmpfile.name
        if orgname:
            args += '-o orgname '
            expected_owner = "orgname"
        else:
            expected_owner = "username"

        parsed_args = self.parser.parse_args(args.split())

        get_method.return_value.json.return_value = {'login': 'username'}

        expected_url = "https://api.github.com/repos/%s/reponame/keys" \
            % expected_owner
        expected_data = {"read_only": False, "title": "%s ssh key" %
                         expected_owner, "key": "ssh-rsa"}
        sfmanager.github_action(parsed_args, "")

        call_args, call_kwargs = post_method.call_args
        self.assertEqual(call_args[0], expected_url)
        self.assertEqual(call_kwargs.get('headers'), self.expected_gh_headers)
        self.assertEqual(call_kwargs.get('json'), expected_data)

        # Remove tmpfile
        try:
            os.remove(tmpfile.name)
        except IOError:
            pass

    def test_deploy_key(self):
        self._test_deploy_key("")

    def test_org_deploy_key(self):
        self._test_deploy_key("orgname")
