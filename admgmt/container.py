"""
.. module:: container

.. TODO:
    * Create this module
"""
# admgmt
# A Python package for managing Active Directory
#
# Copyright (c) 2016 Alex Monroe
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can recieve a copy of the GNU Lesser General Public License
# at <https://www.gnu.org/licenses/lgpl.html>.

# Standard
# Third party
# Package
from . import core

# ADObjectType Constant
AD_OBJ_CONTAINER = core.ADObjectType(
    base_filter='(&(objectCategory=container){})',
    ldap_class=['top', 'container'],
    ldap_category='CN=Container,CN=Schema,CN=Configuration,{}')
