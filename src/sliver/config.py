'''
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
'''

import json
from typing import Type, TypeVar, Union


T = TypeVar('T', bound='SliverClientConfig')
class SliverClientConfig(object):

    def __init__(self, operator: str, lhost: str, lport: int, ca_certificate: str, certificate: str, private_key: str):
        '''
        This class parses and represents Sliver operator configuration files, typically this class is automatically
        instanciated using one of the class methods :class:`SliverClientConfig.parse_config()` or :class:`SliverClientConfig.parse_config_file()` but can be directly
        instanciated too.

        :param operater: Operator name, note that this value is only used by the client and is ignored by the server.
        :param lhost: The listener host to connect to (i.e., the Sliver server host).
        :param lhost: The TCP port of the host listener (i.e., the TCP port of the Sliver "multiplayer" service).
        :param ca_certificate: The Sliver server certificate authority.
        :param certificate: The mTLS client certificate.
        :param private_key: The mTLS private key. 

        :raises ValueError: A parameter contained an invalid value.
        '''
        self.operator = operator
        self.lhost = lhost
        if not 0 < lport < 65535:
            raise ValueError('Invalid lport %d' % lport)
        self.lport = lport
        self.ca_certificate = ca_certificate
        self.certificate = certificate
        self.private_key = private_key

    def __str__(self):
        return '%s@%s%d' % (self.operator, self.lhost, self.lport,)
    
    def __repr__(self):
        return '<Operator: %s, Lhost: %s, Lport: %d, CA: %s, Cert: %s>' % (
            self.operator, self.lhost, self.lport, self.ca_certificate, self.certificate
        )

    @classmethod
    def parse_config(cls: Type[T], data: Union[str, bytes]) -> T:
        '''Parses the content of a Sliver operator configuration file and
        returns the instanciated :class:`SliverClientConfig`

        :param data: The Sliver operator configuration file content.
        :type data: Union[str, bytes]
        :return: An instanciated :class:`SliverClientConfig` object.
        :rtype: T
        '''        
        return cls(**json.loads(data))

    @classmethod
    def parse_config_file(cls: Type[T], filepath: str) -> T:
        """Parse a given file path as a Sliver operator configuration file.

        :param filepath: File system path to an operator configuration file.
        :type filepath: str
        :return: An instanciated :class:`SliverClientConfig` object.
        :rtype: T
        """        
        with open(filepath, 'r') as fp:
            data = fp.read()
        return cls.parse_config(data)
