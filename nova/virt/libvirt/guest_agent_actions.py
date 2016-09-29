# Copyright (c) 2016 LeTV Cloud Computing
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

import base64
import crypt
import re

try:
    import libvirt_qemu
except ImportError:
    libvirt_qemu = None

from oslo_log import log as logging
from oslo_serialization import jsonutils

from nova import exception
from nova.i18n import _
from nova.i18n import _LW
from nova import utils

guest_info = "guest-info"
guest_fopen = "guest-file-open"
guest_fread = "guest-file-read"
guest_fwrite = "guest-file-write"
guest_fclose = "guest-file-close"
guest_set_password = "guest-set-user-password"

QEMU_GUEST_INFO = '{"execute": "%s"}' % guest_info

COMMAND_ARG = '{"execute": "%s", "arguments": %s}'
FILE_OPEN_READ = COMMAND_ARG % (guest_fopen, '{"path": "%s", "mode": "r"}')
FILE_OPEN_WRITE = COMMAND_ARG % (guest_fopen, '{"path": "%s", "mode": "w+"}')
FILE_READ = COMMAND_ARG % (guest_fread, '{"handle": %d,"count": %d}')
FILE_WRITE = COMMAND_ARG % (guest_fwrite, '{"handle": %d,"buf-b64": "%s"}')
FILE_CLOSE = COMMAND_ARG % (guest_fclose, '{"handle": %d}')

# Use crypted password by default
SET_PASSWORD = COMMAND_ARG % (
    guest_set_password,
    '{"crypted": True,"username": "%s", "password": "%s"}')

SHADOW_PATH = "/etc/shadow"
ROOT_KEY_PATH = "/root/.ssh/authorized_keys"
USER_KEY_PATH = "/home/%s/.ssh/authorized_keys"
CMD_TIMEOUT = 30
CMD_RET_FLAG = 0

# Only read 1M
FILE_READ_SIZE = 1024000

LOG = logging.getLogger(__name__)


def _run_qemu_agent_command(domain, param):
    try:
        stream = libvirt_qemu.qemuAgentCommand(domain,
                                               param,
                                               CMD_TIMEOUT,
                                               CMD_RET_FLAG)
        return None if not stream else jsonutils.loads(stream)
    except Exception as ex:
        msg = _LW("Qemu agent command "
                  "'%(param)s' run failed: %(ex)s") % {"param": param,
                                                       "ex": ex}
        LOG.warning(msg)
        raise exception.NovaException(msg)


def read_guest_file(domain, path):
    file_handle = -1
    try:
        file_handle = _run_qemu_agent_command(
            domain,
            FILE_OPEN_READ % path)["return"]
        file_content = _run_qemu_agent_command(
            domain,
            FILE_READ % (file_handle,
                         FILE_READ_SIZE))["return"]
        if not file_content['eof']:
            msg = _LW("Password file size is more than 1M.")
            LOG.warning(msg)
            raise exception.NovaException(msg)
        if file_content['count'] <= 0:
            raise exception.NovaException(
                _("Password file is empty."))
        read_content = file_content["buf-b64"]
    except Exception as ex:
        LOG.warning(_LW("Read file run failed: %s") % ex)
        return None
    finally:
        _run_qemu_agent_command(domain, FILE_CLOSE % file_handle)
    return read_content


def write_guest_file(domain, path, content):
    file_handle = -1
    try:
        file_handle = _run_qemu_agent_command(
            domain,
            FILE_OPEN_WRITE % path)["return"]
        return _run_qemu_agent_command(
            domain,
            FILE_WRITE % (file_handle, content))["return"]["count"]
    except Exception as ex:
        LOG.warning(_LW("Write file run failed: %s") % ex)
    finally:
        _run_qemu_agent_command(domain,
                                FILE_CLOSE % file_handle)


def generate_password(pwd):
    salt = utils.generate_password()
    return crypt.crypt(pwd, "$6$%s" % salt)


def change_password_by_shadow_file(domain, user, pwd):
    read_content = read_guest_file(domain, SHADOW_PATH)
    if read_content:
        pwd_content = base64.standard_b64decode(read_content)
        pwd_arry = re.split("\n", pwd_content)
        for i, line in enumerate(pwd_arry):
            info = line.split(":")
            if info[0] == user:
                info[1] = generate_password(pwd)
                pwd_arry[i] = ":".join(info)
        pwd_write = base64.standard_b64encode("\n".join(pwd_arry))
        write_count = write_guest_file(domain, SHADOW_PATH, pwd_write)
        return write_count > 0


def change_password_by_qagent_cmd(domain, user, pwd):
    try:
        _run_qemu_agent_command(
            domain,
            SET_PASSWORD % (user, generate_password(pwd)))
        return True
    except Exception as ex:
        msg = _LW("Get supported commands run failed: %s") % ex
        LOG.warning(msg)
        raise exception.NovaException(msg)


def _get_user_authorized_keys_path(user):
    if user == 'root':
        return ROOT_KEY_PATH
    return USER_KEY_PATH % user


def change_keypair_by_shadow_file(domain, user, key):
    key_write = base64.standard_b64encode(key)
    path = _get_user_authorized_keys_path(user)
    write_count = write_guest_file(domain, path, key_write)
    return write_count > 0


def _cmd_enabled(cmd, supported_commands):
    for sp_cmd in supported_commands:
        if sp_cmd["enabled"] and sp_cmd["name"] == cmd:
            return True
    return False


def _can_modify_guest_file(supported_commands):
    if (_cmd_enabled("guest-file-open", supported_commands)
            and _cmd_enabled("guest-file-close", supported_commands)
            and _cmd_enabled("guest-file-read", supported_commands)
            and _cmd_enabled("guest-file-write", supported_commands)):
        return True
    return False


def _get_guest_info(domain):
    supported_commands = []
    try:
        supported_commands = _run_qemu_agent_command(
            domain,
            QEMU_GUEST_INFO)["return"]["supported_commands"]
    except Exception as ex:
        msg = _LW("Get supported commands run failed: %s") % ex
        LOG.warning(msg)
        raise exception.NovaException(msg)
    return supported_commands


def reset_admin_password(domain, user, pwd):
    supported_commands = _get_guest_info(domain)
    if _cmd_enabled("guest-set-user-password", supported_commands):
        return change_password_by_qagent_cmd(domain, user, pwd)

    if _can_modify_guest_file(supported_commands):
        return change_password_by_shadow_file(domain, user, pwd)

    msg = _('QEMU guest agent has no available commands.')
    raise exception.NovaException(msg)


def reset_keypair(domain, user, key):
    supported_commands = _get_guest_info(domain)

    if _can_modify_guest_file(supported_commands):
        return change_keypair_by_shadow_file(domain, user, key)

    msg = _('QEMU guest agent has no available commands.')
    raise exception.NovaException(msg)
