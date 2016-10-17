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

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    for table_prefix in ('', 'shadow_'):
        src_pool = Column('src_pool', String(255), nullable=True)
        migrations = Table('%smigrations' % table_prefix, meta)
        if not hasattr(migrations.c, 'src_pool'):
            migrations.create_column(src_pool)

    for table_prefix in ('', 'shadow_'):
        dest_pool = Column('dest_pool', String(255), nullable=True)
        migrations = Table('%smigrations' % table_prefix, meta)
        if not hasattr(migrations.c, 'dest_pool'):
            migrations.create_column(dest_pool)
