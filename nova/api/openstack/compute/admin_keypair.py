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

from webob import exc

from nova.api.openstack import common
from nova.api.openstack.compute.schemas import admin_keypair
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova.api import validation
from nova import compute
from nova import exception
from nova.i18n import _


ALIAS = "os-admin-keypair"
authorize = extensions.os_compute_authorizer(ALIAS)


class AdminKeypairController(wsgi.Controller):

    def __init__(self, *args, **kwargs):
        super(AdminKeypairController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API(skip_policy_check=True)
        self.keypair_api = compute.api.KeypairAPI()

    @wsgi.action('changeKeypair')
    @wsgi.response(202)
    @extensions.expected_errors((400, 404, 409, 501))
    @validation.schema(admin_keypair.change_keypair)
    def change_keypair(self, req, id, body):
        context = req.environ['nova.context']
        authorize(context)

        key_name = body['changeKeypair']['keypairName']
        keypair = common.get_key_pair(self.keypair_api,
                                      context,
                                      key_name)
        instance = common.get_instance(self.compute_api, context, id)
        try:
            self.compute_api.set_keypair(context, instance, keypair)
        except exception.InstanceUnknownCell as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except (exception.InstanceAdminKeypairSetFailed,
                exception.VirtTypeNotSupported,
                exception.Invalid) as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as e:
            raise common.raise_http_conflict_for_instance_invalid_state(
                e, 'changeKeypair', id)
        except NotImplementedError:
            msg = _("Unable to set admin keypair on instance")
            common.raise_feature_not_supported(msg=msg)


class AdminKeypair(extensions.V21APIExtensionBase):
    """Admin keypair management support."""

    name = "AdminKeypair"
    alias = ALIAS
    version = 1

    def get_resources(self):
        return []

    def get_controller_extensions(self):
        controller = AdminKeypairController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
