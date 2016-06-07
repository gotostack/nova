# Copyright 2016 LeTV Cloud Computing.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import mock
import webob

from nova.api.openstack.compute import admin_keypair as admin_keypair_v21
from nova.api.openstack.compute.legacy_v2 import servers
from nova.compute import api as compute_api
from nova import exception
from nova import test
from nova.tests.unit.api.openstack import fakes


def fake_get(self, context, id, expected_attrs=None, want_objects=False):
    return {'uuid': id}


def fake_set_keypair(self, context, instance, key):
    pass


class AdminKeypairTestV21(test.NoDBTestCase):
    validiation_error = exception.ValidationError

    def setUp(self):
        super(AdminKeypairTestV21, self).setUp()
        self.stubs.Set(compute_api.API, 'set_keypair',
                       fake_set_keypair)
        self.stubs.Set(compute_api.API, 'get', fake_get)
        self.fake_req = fakes.HTTPRequest.blank('')

    def _get_action(self):
        return admin_keypair_v21.AdminKeypairController().change_keypair

    def _check_status(self, expected_status, res, controller_method):
        self.assertEqual(expected_status, controller_method.wsgi_code)

    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair(self, mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        res = self._get_action()(self.fake_req, '1', body=body)
        self._check_status(202, res, self._get_action())

    def test_change_keypair_empty_string(self):
        body = {'changeKeypair': {'keypairName': ''}}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    @mock.patch('nova.compute.api.API.set_keypair',
                side_effect=NotImplementedError())
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_with_non_implement(self,
                                               mock_set_admin_keypair,
                                               mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPNotImplemented,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    @mock.patch('nova.compute.api.API.get',
                side_effect=exception.InstanceNotFound(instance_id='1'))
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_with_non_existed_instance(self,
                                                      mock_get,
                                                      mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPNotFound,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    def test_change_keypair_with_non_string_keypair(self):
        body = {'changeKeypair': {'keypairName': 1234}}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    @mock.patch('nova.compute.api.API.set_keypair',
                side_effect=exception.InstanceAdminKeypairSetFailed(
                    instance="1", reason=''))
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_failed(self,
                                   mock_set_admin_keypair,
                                   mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPConflict,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    def test_change_keypair_without_admin_keypair(self):
        body = {'changeKeypair': {}}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    def test_change_keypair_none(self):
        body = {'changeKeypair': {'keypairName': None}}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    def test_change_keypair_adminpass_none(self):
        body = {'changeKeypair': None}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    def test_change_keypair_bad_request(self):
        body = {'changeKeypair': {'pass': '12345'}}
        self.assertRaises(self.validiation_error,
                          self._get_action(),
                          self.fake_req, '1', body=body)

    @mock.patch('nova.compute.api.API.set_keypair',
                side_effect=exception.InstanceInvalidState(
                    instance_uuid='fake', attr='vm_state', state='stopped',
                    method='set_keypair'))
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_invalid_state(self,
                                          mock_set_admin_keypair,
                                          mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPConflict,
                          self._get_action(),
                          self.fake_req, 'fake', body=body)

    @mock.patch('nova.compute.api.API.set_keypair',
                side_effect=exception.VirtTypeNotSupported(instance="1",
                                                           reason=''))
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_virt_type_not_supported(self,
                                                    mock_set_admin_keypair,
                                                    mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPConflict,
                          self._get_action(),
                          self.fake_req, 'fake', body=body)

    @mock.patch('nova.compute.api.API.set_keypair',
                side_effect=exception.Invalid(instance="1",
                                              reason=''))
    @mock.patch('nova.compute.api.KeypairAPI.get_key_pair',
                return_value=mock.Mock())
    def test_change_keypair_guest_agent_no_enabled(self,
                                                   mock_set_admin_keypair,
                                                   mock_get_key_pair):
        body = {'changeKeypair': {'keypairName': 'test'}}
        self.assertRaises(webob.exc.HTTPConflict,
                          self._get_action(),
                          self.fake_req, 'fake', body=body)


class AdminKeypairTestV2(AdminKeypairTestV21):
    validiation_error = webob.exc.HTTPBadRequest

    def _get_action(self):
        class FakeExtManager(object):
            def is_loaded(self, ext):
                return False
        return servers.Controller(
            ext_mgr=FakeExtManager())._action_change_keypair

    def _check_status(self, expected_status, res, controller_method):
        self.assertEqual(expected_status, res.status_int)


class AdminKeypairPolicyEnforcementV21(test.NoDBTestCase):

    def setUp(self):
        super(AdminKeypairPolicyEnforcementV21, self).setUp()
        self.controller = admin_keypair_v21.AdminKeypairController()
        self.req = fakes.HTTPRequest.blank('')

    def test_change_keypair_policy_failed(self):
        rule_name = "os_compute_api:os-admin-keypair"
        rule = {rule_name: "project:non_fake"}
        self.policy.set_rules(rule)
        body = {'changeKeypair': {'keypairName': 'keyname'}}
        exc = self.assertRaises(
            exception.PolicyNotAuthorized, self.controller.change_keypair,
            self.req, fakes.FAKE_UUID, body=body)
        self.assertEqual(
            "Policy doesn't allow %s to be performed." % rule_name,
            exc.format_message())
