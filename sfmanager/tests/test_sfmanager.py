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
import json
import os
from mock import patch, MagicMock
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
            with patch('requests.' + method_verb) as method:
                method.return_value = FakeResponse(json_data=returned_json)
                parsed = self.parser.parse_args(cmd_args)
                params = {'headers': self.headers, 'cookies': self.cookies}
                self.assertTrue(action_func(parsed, self.base_url,
                                            self.headers))

                # Here there if is an issue about deserialization
                # of data that make assert_called_with to fail
                # randomly. Not the best way but retries a couple of
                # time before raising an error
                for i in xrange(5):
                    try:
                        if expected_data is not None:
                            params['data'] = json.dumps(expected_data)
                        method.assert_called_with(expected_url, **params)
                        break
                    except Exception:
                        pass


class TestProjectUserAction(BaseFunctionalTest):
    def test_create_project(self):
        args = self.default_args
        args += 'project create --name proj1'.split()
        expected_url = self.base_url + 'project/proj1/'
        self.assert_secure('put', args,
                           sfmanager.project_action, expected_url)

    def test_create_project_named_with_namespace(self):
        args = self.default_args
        args += 'project create --name ns1/proj1'.split()
        name = '===' + base64.urlsafe_b64encode('ns1/proj1')
        expected_url = self.base_url + 'project/%s/' % name
        self.assert_secure('put', args,
                           sfmanager.project_action, expected_url)

    def test_create_project_with_branches(self):
        cmd = ('project create --name proj2 '
               '--upstream ssh://tests.dom/test.git --add-branches')
        args = self.default_args
        args += cmd.split()
        excepted_url = self.base_url + 'project/proj2/'
        self.assert_secure('put', args, sfmanager.project_action, excepted_url,
                           {'upstream': 'ssh://tests.dom/test.git',
                            'add-branches': True})

    def test_delete_project(self):
        args = self.default_args
        args += 'project delete --name proj1'.split()
        expected_url = self.base_url + 'project/proj1/'
        self.assert_secure('delete', args,
                           sfmanager.project_action, expected_url)


class TestTestsActions(BaseFunctionalTest):
    def test_init_test_project(self):
        args = self.default_args
        args += 'tests init --project toto'.split()
        expected_url = self.base_url + 'tests/toto/'
        self.assert_secure('put', args,
                           sfmanager.tests_action, expected_url,
                           {'project-scripts': True})

    def test_init_test_project_no_scripts(self):
        args = self.default_args
        args += 'tests init --project toto --no-scripts'.split()
        expected_url = self.base_url + 'tests/toto/'
        self.assert_secure('put', args,
                           sfmanager.tests_action, expected_url,
                           {'project-scripts': False})


class TestJobsActions(BaseFunctionalTest):
    def test_list_jobs(self):
        args = self.default_args
        args += 'job list --job-name toto'.split()
        expected_url = self.base_url + 'jobs/toto'
        returned_json = {'jenkins': [{'job_name': 'toto',
                                      'job_id': 4,
                                      'status': 'SUCCESS'}, ]}
        self.assert_secure('get', args,
                           sfmanager.job_action, expected_url,
                           returned_json=returned_json)

    def test_logs(self):
        args = self.default_args
        args += 'job logs --job-name toto --id 4'.split()
        expected_url = self.base_url + 'jobs/toto/id/4/logs'
        returned_json = {'jenkins': {'job_name': 'toto',
                                     'job_id': 4,
                                     'logs_url': 'aaaa'}}
        self.assert_secure('get', args,
                           sfmanager.job_action, expected_url,
                           returned_json=returned_json)

    def test_parameters(self):
        args = self.default_args
        args += 'job parameters --job-name toto --id 4'.split()
        expected_url = self.base_url + 'jobs/toto/id/4/parameters'
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
                           sfmanager.job_action, expected_url,
                           returned_json={'jenkins': {'job_name': 'toto',
                                                      'job_id': 2,
                                                      'status': 'PENDING'}})

    def test_stop(self):
        args = self.default_args
        args += 'job stop --job-name toto --id 2'.split()
        expected_url = self.base_url + 'jobs/toto/id/2'
        self.assert_secure('delete', args,
                           sfmanager.job_action, expected_url,
                           returned_json={'jenkins': {'job_name': 'toto',
                                                      'job_id': 2,
                                                      'status': 'ABORTED'}})


class TestMembershipAction(BaseFunctionalTest):
    def test_project_add_user_to_groups(self):
        args = self.default_args
        project_name = 'ns2/prj1'
        c = 'membership add --user u --project %s' % project_name
        c += ' --groups dev-group ptl-group'
        args += c.split()
        encoded_name = '===' + base64.urlsafe_b64encode(project_name)
        url = self.base_url + 'project/membership/%s/u/' % encoded_name
        self.assert_secure('put', args,
                           sfmanager.membership_action, url,
                           {'groups': ['dev-group', 'ptl-group']})

    def test_project_remove_user_from_all_groups(self):
        args = self.default_args
        cmd = 'membership remove --user user1 --project ns2/prj1'
        args += cmd.split()
        encoded_name = '===' + base64.urlsafe_b64encode('ns2/prj1')
        url = self.base_url + 'project/membership/%s/user1/' % encoded_name
        self.assert_secure('delete', args, sfmanager.membership_action,
                           url)

    def test_project_remove_user_from_group(self):
        args = self.default_args
        cmd = 'membership remove --user u1 --project proj1 --group dev-group'
        args += cmd.split()
        url = self.base_url + 'project/membership/proj1/u1/dev-group/'
        self.assert_secure('delete', args, sfmanager.membership_action, url)


class TestGroupActions(BaseFunctionalTest):
    def test_group_create(self):
        args = self.default_args
        data = {'description': 'desc'}
        cmd = 'group create -n grp1 -d {description}'
        args += cmd.format(**data).split()
        expected_url = self.base_url + 'group/grp1/'
        self.assert_secure('put', args, sfmanager.groups_management_action,
                           expected_url, data)

    def test_group_delete(self):
        args = self.default_args
        cmd = 'group delete -n grp1'
        args += cmd.split()
        expected_url = self.base_url + 'group/grp1/'
        self.assert_secure('delete', args, sfmanager.groups_management_action,
                           expected_url)

    def test_group_get_all(self):
        args = self.default_args
        cmd = 'group list'
        args += cmd.split()
        expected_url = self.base_url + 'group/'
        self.assert_secure('get', args, sfmanager.groups_management_action,
                           expected_url,
                           returned_json={'grp1': {'description': "",
                                                   'members': []}})

    def test_group_get_one(self):
        args = self.default_args
        cmd = 'group list -n grp1'
        args += cmd.split()
        expected_url = self.base_url + 'group/grp1/'
        self.assert_secure('get', args, sfmanager.groups_management_action,
                           expected_url,
                           returned_json={'grp1': [{'email': "",
                                                    'username': "",
                                                    'name': ""}]})

    def test_group_add_remove(self):
        args = self.default_args
        data = {'members': ['user1@sftests.com', 'user2@sftests.com']}
        cmd = 'group add -n grp1 -e user1@sftests.com user2@sftests.com'
        args += cmd.format(**data).split()
        expected_url = self.base_url + 'group/grp1/'
        with patch('requests.get'):
            self.assert_secure('post', args,
                               sfmanager.groups_management_action,
                               expected_url, data)


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
        self.assert_secure('post', args, sfmanager.user_management_action,
                           expected_url, returned_json=data)

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

    def test_restore(self):
        args = self.default_args
        args += 'system restore --filename tmp_backup'.split()
        expected_url = self.base_url + 'restore/'
        with open('tmp_backup', 'a') as toto:
            toto.write(' ')

        with patch('sfmanager.sfmanager.get_cookie') as c:
            c.return_value = 'fake_cookie'
            test_mock = 'sfmanager.sfmanager.open'
            with patch(test_mock, create=True) as mock_open:
                mock_open.return_value = MagicMock(spec=file)
                with patch('requests.post') as method:
                    method.return_value = FakeResponse()
                    parsed = self.parser.parse_args(args)
                    params = {'headers': self.headers, 'cookies': self.cookies}
                    params['files'] = {'file': mock_open.return_value}
                    self.assertTrue(sfmanager.backup_action(parsed,
                                                            self.base_url,
                                                            self.headers))
                    method.assert_called_with(expected_url, **params)


class TestGithubActions(BaseFunctionalTest):
    def test_create_repo(self):
        args = '--github-token ghtoken github create-repo -n reponame'.split()
        parsed_args = self.parser.parse_args(args)

        expected_url = "https://api.github.com/user/repos"
        expected_data = {"name": "reponame", "private": False}

        with patch('requests.post') as method:
            sfmanager.github_action(parsed_args, "", {})

            call_args, call_kwargs = method.call_args
            self.assertEqual(call_args[0], expected_url)
            self.assertEqual(call_kwargs.get('headers'),
                             self.expected_gh_headers)
            self.assertEqual(json.loads(call_kwargs.get('data')),
                             expected_data)

    def test_create_org_repo(self):
        args = '--github-token ghtoken '
        args += 'github create-repo -n reponame -o orgname'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/orgs/orgname/repos"
        expected_data = {"name": "reponame", "private": False}

        with patch('requests.post') as method:
            sfmanager.github_action(parsed_args, "", {})

            call_args, call_kwargs = method.call_args
            self.assertEqual(call_args[0], expected_url)
            self.assertEqual(call_kwargs.get('headers'),
                             self.expected_gh_headers)
            self.assertEqual(json.loads(call_kwargs.get('data')),
                             expected_data)

    def test_fork_repo(self):
        args = '--github-token ghtoken github fork-repo '
        args += '--fork https://github.com/openstack/swift '
        args += '--name swift'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/repos/openstack/swift/forks"

        with patch('requests.post') as method:
            with patch('requests.patch'):
                sfmanager.github_action(parsed_args, "", {})

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
                sfmanager.github_action(parsed_args, "", {})

                call_args, call_kwargs = method.call_args
                self.assertEqual(call_args[0], expected_url)
                self.assertEqual(call_kwargs.get('headers'),
                                 self.expected_gh_headers)

        expected_data = {"organization": "rdo-packages"}
        self.assertEqual(json.loads(call_kwargs.get('data')), expected_data)

    @patch('requests.delete')
    @patch('requests.get')
    def test_delete_repo(self, get_method, delete_method):
        args = '--github-token ghtoken github delete-repo -n reponame'.split()
        parsed_args = self.parser.parse_args(args)

        get_method.return_value.json.return_value = {'login': 'username'}
        expected_url = "https://api.github.com/repos/username/reponame"
        kwargs = {'headers': self.expected_gh_headers}
        sfmanager.github_action(parsed_args, "", {})
        delete_method.assert_called_with(expected_url, **kwargs)

    @patch('requests.delete')
    @patch('requests.get')
    def test_delete_org_repo(self, get_method, delete_method):
        args = '--github-token ghtoken '
        args += 'github delete-repo -n reponame -o orgname'
        parsed_args = self.parser.parse_args(args.split())

        expected_url = "https://api.github.com/repos/orgname/reponame"
        kwargs = {'headers': self.expected_gh_headers}
        sfmanager.github_action(parsed_args, "", {})
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
        sfmanager.github_action(parsed_args, "", {})

        call_args, call_kwargs = post_method.call_args
        self.assertEqual(call_args[0], expected_url)
        self.assertEqual(call_kwargs.get('headers'), self.expected_gh_headers)
        self.assertEqual(json.loads(call_kwargs.get('data')), expected_data)

        # Remove tmpfile
        try:
            os.remove(tmpfile.name)
        except IOError:
            pass

    def test_deploy_key(self):
        self._test_deploy_key("")

    def test_org_deploy_key(self):
        self._test_deploy_key("orgname")
