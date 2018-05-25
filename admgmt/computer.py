"""
.. module:: computer

.. TODO:
    * create docstrings for functions
    * validate functions
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
import ldap3
import ldap3.utils.ciDict
import ldap3.utils.dn
# Package
from . import core
from . import utils

# ADObjectType Constant
AD_OBJ_COMPUTER = core.ADObjectType(
    base_filter='(&(objectCategory=computer){})',
    ldap_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
    ldap_category='CN=Computer,CN=Schema,CN=Configuration,{}',
    def_id_filter='(sAMAccountName={}$)')

# <get_ad_computer>
def get_ad_computer(connection,
                    identity=None,
                    properties=None,
                    search_base=None,
                    search_scope=core.SCOPE_SUBTREE):
    """
    The ``get_ad_computer`` function gets one or more Active Directory
    computers by performing a search against Active Directory using
    ldap.

    This function gets a default set of Active Directory object
    properties. To get additional properties use the ``properties``
    parameter.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        [Optional] Specifies an Active Directory computer object by
        providing one of the following property values. The identifier
        in parentheses is the LDAP display name for the attribute. If
        not specified all computer objects are returned within the
        bounds of the ``search_base`` and ``search_scope`` (which by
        default would be all computers).

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisDesktop,CN=Computers,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisdesktop``

        You can also use ``identity`` to manually specify an LDAP query
        string. This supports the same functionality as the LDAP
        syntax, but take note that some additional search filters will
        be added to whatever you specify so that only computer objects
        are returned by the operation.

    properties : str or list
        [Optional] Specifies the properties of the object to retrieve
        from the server. Use this parameter to retrieve properties that
        are not included in the default set.

        To display all of the attributes that are set on the object,
        specify * (asterisk).

    search_base : str
        [Optional] Specifies the distinguished name of an Active
        Directory path to search under. The default value of this
        parameter is the root of the domain specified in the
        ``connection`` parameter.

    search_scope : admgmt constant
        [Optional] Specifies the scope of an Active Directory search.
        Possible values for this parameter are defined in ``admgmt``
        and are SCOPE_BASE, SCOPE_LEVEL, or SCOPE_SUBTREE.

        The default scope is SCOPE_SUBTREE.

    Returns
    -------
    list
        A list of ADObject objects

    Examples
    --------
    Create a new connection object and get the specified computer::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.computer import get_ad_computer
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> ad_computer = get_ad_computer(conn, 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_COMPUTER, identity)
    properties = utils.safe_str_or_list(properties)
    search_base = utils.safe_dn(search_base)
    search_scope = utils.safe_scope(search_scope)

    # Get list of attributes to gather
    if properties == '*':
        attributes = [ldap3.ALL_ATTRIBUTES]
    else:
        attributes = utils.convert_to_lowercase_list(
            base=['dNSHostName', 'name', 'sAMAccountName'],
            combine_with=properties
        )

    # Get the computer object(s)
    return core.get_ad_object(
        connection=connection,
        search_filter=identity.search_filter,
        properties=attributes,
        search_base=search_base,
        search_scope=search_scope
    )

# </get_ad_computer>

# <move_ad_computer>
def move_ad_computer(connection,
                     identity,
                     new_path):
    """
    The ``move_ad_computer`` function moves a computer from one
    container to another.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory computer object by providing one
        of the following property values. The identifier in parentheses
        is the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisDesktop,CN=Computers,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisdesktop``

    new_path : str
        Specifies the distinguished name of the Active Directory path
        to move the computer to.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and moves the specified computer::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.computer import move_ad_computer
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> move_ad_computer(conn, 'saradavisdesktop', 'OU=Devices,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_COMPUTER, identity)
    new_path = utils.safe_dn(new_path)

    # Get the computer account
    computer = get_ad_computer(connection=connection, identity=identity)
    if not computer:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a computer matching %s" % str(identity))

    # Move the computer account
    core.move_ad_object(
        connection=connection,
        path=computer[0].path,
        new_path=new_path
    )

# </move_ad_computer>

# <new_ad_computer>
def new_ad_computer(connection,
                    name,
                    path=None,
                    attributes=None):
    """
    The ``new_ad_computer`` function creates a new Active Directory
    computer.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    name : str
        Specifies the name of the new computer. By default this
        parameter sets the ``cn``, ``name``, and ``sAMAccountName`` of
        the new computer. To set different values for these properties
        use the ``attributes`` parameter.

    path : str
        [Optional] Specifies the distinguished name of the Active
        Directory path to create the new_ad_computer in. If not
        specified, computers are created created in the Computers
        container.

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and creates the specified computer::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.computer import new_ad_computer
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> new_ad_computer(conn, 'saradavisdesktop')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    name = utils.safe_str(name)
    path = utils.safe_dn(path)
    attributes = utils.safe_dict(attributes)

    # Apply a default path if none specified
    if not path:
        path = "CN=Computers,%s" % connection.domain_dn

    # Put together computer distinguished name
    computer_dn = "CN=%s,%s" % (name, path)

    # Combine the defaults with the specified attributes
    settings = utils.convert_to_lowercase_dict(
        base={
            'cn': name,
            'name': name,
            'sAMAccountName': "%s$" % name.upper(),
            'userAccountControl': str(core.UAC_WORKSTATION_TRUST_ACCOUNT)},
        combine_with=attributes
    )

    # Create computer
    core.new_ad_object(
        connection=connection,
        path=computer_dn,
        obj_type=AD_OBJ_COMPUTER,
        attributes=settings
    )

# </new_ad_computer>

# <remove_ad_computer>
def remove_ad_computer(connection,
                       identity):
    """
    The ``remove_ad_computer`` function removes an Active Directory
    computer.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory computer object by providing one
        of the following property values. The identifier in parentheses
        is the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisDesktop,CN=Computers,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisdesktop``

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and removes the specified computer::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.computer import remove_ad_computer
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> remove_ad_computer(conn, 'saradavisdesktop')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_COMPUTER, identity)

    # Get the computer account
    computer = get_ad_computer(connection=connection, identity=identity)
    if not computer:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a computer matching %s" % str(identity))

    # Remove the computer account
    core.remove_ad_object(
        connection=connection,
        path=computer[0].path
    )

# </remove_ad_computer>

# <set_ad_computer>
def set_ad_computer(connection,
                    identity,
                    attributes):
    """
    The ``set_ad_computer`` function modifies the attributes of an Active
    Directory computer.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory computer object by providing one
        of the following property values. The identifier in parentheses
        is the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisDesktop,CN=Computers,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisdesktop``

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and modifies the specified computer::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.computer import set_ad_computer
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_computer(conn, 'saradavisdesktop', {'description': 'Sara'})
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_COMPUTER, identity)
    attributes = utils.safe_dict(attributes)

    # Get the computer account
    computer = get_ad_computer(connection=connection, identity=identity)
    if not computer:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a computer matching %s" % str(identity))

    # Apply the changes
    core.set_ad_object(
        connection=connection,
        path=computer[0].path,
        attributes=attributes
    )

# </set_ad_computer>
