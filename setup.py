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

import setuptools
from docs.conf import AUTHOR, VERSION


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sliver-py",
    version=VERSION,
    author=AUTHOR,
    author_email="875022+moloch--@users.noreply.github.com",
    description="Sliver gRPC client library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moloch--/sliver-py",
    project_urls={
        "Bug Tracker": "https://github.com/moloch--/sliver-py/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    install_requires=[
        'grpcio',
        'grpcio-tools',
    ],
    package_dir={"": "src"},
    packages=[
        'sliver',
        'sliver.pb',
        'sliver.pb.commonpb',
        'sliver.pb.sliverpb',
        'sliver.pb.clientpb',
        'sliver.pb.rpcpb',
    ],
    python_requires=">=3.6",
    include_package_data=True
)