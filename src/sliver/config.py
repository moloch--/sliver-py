"""
Sliver Implant Framework
Copyright (C) 2021  Bishop Fox
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
from typing import Type, TypeVar, Union


T = TypeVar('T', bound='SliverClientConfig')
class SliverClientConfig(object):

    def __init__(self, operator: str, lhost: str, lport: int, ca_certificate: str, certificate: str, private_key: str):
        self.operator = operator
        self.lhost = lhost
        if not 0 < lport < 65535:
            raise ValueError('Invalid lport %d' % lport)
        self.lport = lport
        self.ca_certificate = ca_certificate
        self.certificate = certificate
        self.private_key = private_key

    @classmethod
    def parse_config(cls: Type[T], data: Union[str, bytes]) -> T:
        return cls(**json.loads(data))

    @classmethod
    def parse_config_file(cls: Type[T], filepath: str) -> T:
        with open(filepath, 'r') as fp:
            data = fp.read()
        return cls.parse_config(data)
