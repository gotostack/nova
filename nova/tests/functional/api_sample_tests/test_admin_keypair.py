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

import uuid

from oslo_config import cfg

from nova.tests.functional.api_sample_tests import test_servers

CONF = cfg.CONF
CONF.import_opt('osapi_compute_extension',
                'nova.api.openstack.compute.legacy_v2.extensions')


class AdminKeypairJsonTest(test_servers.ServersSampleBase):
    extension_name = 'os-admin-keypair'
    expected_post_status_code = 200

    def _get_flags(self):
        f = super(AdminKeypairJsonTest, self)._get_flags()
        if self._legacy_v2_code:
            f['osapi_compute_extension'] = CONF.osapi_compute_extension[:]
            f['osapi_compute_extension'].append(
                'nova.api.openstack.compute.contrib.keypairs.Keypairs')
        return f

    # TODO(sdague): this is only needed because we randomly choose the
    # uuid each time.
    def generalize_subs(self, subs, vanilla_regexes):
        subs['keypair_name'] = 'keypair-[0-9a-f-]+'
        return subs

    def _check_keypairs_post(self, **kwargs):
        """Get api sample of key pairs post request."""
        key_name = 'keypair-' + str(uuid.uuid4())
        subs = dict(keypair_name=key_name, **kwargs)
        response = self._do_post('os-keypairs', 'keypairs-post-req', subs)
        subs = {'keypair_name': key_name}

        self._verify_response('keypairs-post-resp', subs, response,
                              self.expected_post_status_code)
        # NOTE(maurosr): return the key_name is necessary cause the
        # verification returns the label of the last compared information in
        # the response, not necessarily the key name.
        return key_name

    def test_admin_keypair(self):
        key_name = self._check_keypairs_post()
        uuid = self._post_server()
        subs = {"keypair_name": key_name}
        response = self._do_post('servers/%s/action' % uuid,
                                 'admin-keypair-change-keypair',
                                 subs)
        self.assertEqual(202, response.status_code)
        self.assertEqual("", response.content)
