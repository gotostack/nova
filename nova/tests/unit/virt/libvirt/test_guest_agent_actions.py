# Copyright (c) 2015 LeTV Cloud Computing
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
from mox3 import mox

from nova import exception
from nova import test
from nova.tests.unit.virt.libvirt import test_driver
from nova.virt.libvirt import guest_agent_actions as ag_actions

GUEST_INFO_FOO = """{
    "return": {
        "version": "9.99",
        "supported_commands": [
        {
            "enabled": true,
            "name": "foo-foo",
            "success-response": true
        },]
    }
}
"""

GUEST_INFO_2_3 = """{
    "return": {
        "version": "2.3",
        "supported_commands": [
        {
            "enabled": true,
            "name": "guest-info",
            "success-response": true
        },
        {
            "enabled": true,
            "name": "guest-set-user-password",
            "success-response": true
        }]
    }
}
"""

GUEST_INFO_2_0 = """{
    "return": {
        "version": "2.0.0",
        "supported_commands": [
        {
            "enabled": true,
            "name": "guest-info",
            "success-response": true
        },
        {
            "enabled": true,
            "name": "guest-file-write",
            "success-response": true
        },
        {
            "enabled": true,
            "name": "guest-file-read",
            "success-response": true
        },
        {
            "enabled": true,
            "name": "guest-file-close",
            "success-response": true
        },
        {
            "enabled": true,
            "name": "guest-file-open",
            "success-response": true
        }]
    }
}
"""

FILE_OPEN = '{"return":1000}'
FILE_READ = """{"return":{"count":34,
"buf-b64":"cm9vdDokNiRXdUNSUy46MTY2MTA6MDo5OTk5OTo3Ojo6Cg==","eof":true}}
"""
FILE_READ_OUT_OF_SIEZE = """{"return":{"count":102400,
"buf-b64":"cm9vdDokNiRXdUNSUy46MTY2MTA6MDo5OTk5OTo3Ojo6Cg==","eof":false}}
"""
FILE_READ_EMPTY = """{"return":{"count":0,
"buf-b64":"","eof":true}}
"""
FILE_WRITE = '{"return": {"count": 1024}}'
FILE_CLOSE = '{"return":{}}'


class QemuAgentActionsTestCase(test.NoDBTestCase):

    def setUp(self):
        super(QemuAgentActionsTestCase, self).setUp()
        self.domain = test_driver.FakeVirtDomain()

    def tearDown(self):
        super(QemuAgentActionsTestCase, self).tearDown()

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_qg_cmd(self, mock_libvirt_qemu):
        crypted_pwd = '$6$1a2c3d'
        self.mox.StubOutWithMock(ag_actions, 'generate_password')
        ag_actions.generate_password('123').AndReturn(crypted_pwd)
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_2_3)

        # guest set user password
        param = ag_actions.SET_PASSWORD % ('root', crypted_pwd)
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG)

        self.mox.ReplayAll()

        ret = ag_actions.reset_admin_password(self.domain, '123')
        self.assertTrue(ret)

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_change_shadow_file(self, mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_2_0)

        # file Open 'r'
        param = ag_actions.FILE_OPEN_READ % ag_actions.SHADOW_PATH
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_OPEN)

        # file read
        param = ag_actions.FILE_READ % (1000,
                                        ag_actions.FILE_READ_SIZE)
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_READ)

        # file close
        param = ag_actions.FILE_CLOSE % 1000
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_CLOSE)

        # file open 'w+'
        param = ag_actions.FILE_OPEN_WRITE % ag_actions.SHADOW_PATH
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_OPEN)

        # file write
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            mox.IgnoreArg(),
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_WRITE)

        # file close
        param = ag_actions.FILE_CLOSE % 1000
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_CLOSE)

        self.mox.ReplayAll()

        ret = ag_actions.reset_admin_password(self.domain, '123')
        self.assertTrue(ret)

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_linux_root_public_keypair(self, mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_2_0)

        # file open 'w+'
        param = ag_actions.FILE_OPEN_WRITE % ag_actions.ROOT_KEY_PATH
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_OPEN)

        # file write
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            mox.IgnoreArg(),
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_WRITE)

        # file close
        param = ag_actions.FILE_CLOSE % 1000
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_CLOSE)

        self.mox.ReplayAll()

        ret = ag_actions.reset_keypair(self.domain, 'key')
        self.assertTrue(ret)

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_qemu_cmd_failed(self, mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndRaise(
                exception.NovaException('foo'))

        self.mox.ReplayAll()

        self.assertRaises(exception.NovaException,
                          ag_actions.reset_admin_password,
                          self.domain, '123')

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_no_func_enable(self, mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_FOO)

        self.mox.ReplayAll()

        self.assertRaises(exception.NovaException,
                          ag_actions.reset_admin_password,
                          self.domain, '123')

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_shadow_file_out_of_size(self,
                                                          mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_2_0)

        # file Open 'r'
        param = ag_actions.FILE_OPEN_READ % ag_actions.SHADOW_PATH
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_OPEN)

        # file read
        param = ag_actions.FILE_READ % (1000,
                                        ag_actions.FILE_READ_SIZE)
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_READ_OUT_OF_SIEZE)

        self.mox.ReplayAll()

        self.assertRaises(exception.NovaException,
                          ag_actions.reset_admin_password,
                          self.domain, '123')

    @mock.patch.object(ag_actions, 'libvirt_qemu')
    def test_reset_admin_password_shadow_file_empty(self, mock_libvirt_qemu):
        self.mox.StubOutWithMock(mock_libvirt_qemu, 'qemuAgentCommand')
        # get agent guest info
        param = ag_actions.QEMU_GUEST_INFO
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(GUEST_INFO_2_0)

        # file Open 'r'
        param = ag_actions.FILE_OPEN_READ % ag_actions.SHADOW_PATH
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_OPEN)

        # file read
        param = ag_actions.FILE_READ % (1000,
                                        ag_actions.FILE_READ_SIZE)
        mock_libvirt_qemu.qemuAgentCommand(
            self.domain,
            param,
            ag_actions.CMD_TIMEOUT,
            ag_actions.CMD_RET_FLAG).AndReturn(FILE_READ_EMPTY)

        self.mox.ReplayAll()

        self.assertRaises(exception.NovaException,
                          ag_actions.reset_admin_password,
                          self.domain, '123')
