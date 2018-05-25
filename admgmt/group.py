"""
.. module:: group

.. TODO:
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
import copy
# Third party
import ldap3
import ldap3.utils.dn
# Module
from . import core
from . import user
from . import computer
from . import utils

# Group Type Constants
GRP_SYSTEM = 1
GRP_SCOPE_GLOBAL = 2
GRP_SCOPE_LOCAL = 4
GRP_SCOPE_UNIVERSAL = 8
GRP_APP_BASIC = 16
GRP_APP_QUERY = 32
GRP_SECURITY = 2147483648

# ADObjectType Constant
AD_OBJ_GROUP = core.ADObjectType(
    base_filter='(&(objectCategory=group){})',
    ldap_class=['top', 'group'],
    ldap_category='CN=Group,CN=Schema,CN=Configuration,{}',
    def_id_filter='(sAMAccountName={})')

# <add_ad_group_member>
def add_ad_group_member(connection,
                        identity,
                        add_user=None,
                        add_group=None,
                        add_computer=None):
    """
    The ``add_ad_group_member`` function adds one or more users,
    groups, service accounts, or computers as new members of an
    Active Directory group.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory group object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    add_user : str or list
        [Optional] Specifies one or more Active Directory user objects
        to add by providing one of the following property values. The
        identifier in parentheses is the LDAP display name for the
        attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    add_group : str or list
        [Optional] Specifies one or more Active Directory group objects
        to add by providing one of the following property values. The
        identifier in parentheses is the LDAP display name for the
        attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    add_computer : str or list
        [Optional] Specifies one or more Active Directory computer
        objects to add by providing one of the following property
        values. The identifier in parentheses is the LDAP display name
        for the attribute.

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
    Create a new connection object and adds a member to the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import add_ad_group_member
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> add_ad_group_member(conn, 'saradavisreports', 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)
    add_user = utils.safe_str_or_list(add_user)
    add_group = utils.safe_str_or_list(add_group)
    add_computer = utils.safe_str_or_list(add_computer)

    # Get the group account
    group = get_ad_group(connection=connection, identity=identity, properties=['member'])
    if not group:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a group matching %s" % str(identity))

    # Initalize the add list and get the current member list
    add_list = []
    if group[0]['member']:
        current_list = utils.convert_to_lowercase_list(group[0]['member'])
    else:
        current_list = []

    # Get users to add
    for user_identity in add_user:
        add_list.extend(user.get_ad_user(
            connection=connection,
            identity=user_identity))

    # Get groups to add
    for group_identity in add_group:
        add_list.extend(get_ad_group(
            connection=connection,
            identity=group_identity))

    # Get computers to add
    for computer_identity in add_computer:
        add_list.extend(computer.get_ad_computer(
            connection=connection,
            identity=computer_identity))

    # Put the new member list together
    new_list = copy.copy(current_list)
    for ad_obj in add_list:
        if ad_obj.path.lower() not in new_list:
            new_list.append(ad_obj.path.lower())

    # Add group members
    if new_list != current_list:
        core.set_ad_object(
            connection=connection,
            path=group[0].path,
            attributes={'member': new_list}
        )

# </add_ad_group_member>

# <get_ad_group>
def get_ad_group(connection,
                 identity=None,
                 properties=None,
                 search_base=None,
                 search_scope=core.SCOPE_SUBTREE):
    """
    The ``get_ad_group`` function gets one or more Active Directory
    groups by performing a search against Active Directory using ldap.

    This function gets a default set of Active Directory object
    properties. To get additional properties use the ``properties``
    parameter.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        [Optional] Specifies an Active Directory group object by
        providing one of the following property values. The identifier
        in parentheses is the LDAP display name for the attribute. If
        not specified all group objects are returned within the bounds
        of the ``search_base`` and ``search_scope`` (which by default
        would be all groups).

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

        You can also use ``identity`` to manually specify an LDAP query
        string. This supports the same functionality as the LDAP
        syntax, but take note that some additional search filters will
        be added to whatever you specify so that only group objects are
        returned by the operation.

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
    Create a new connection object and get the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import get_ad_group
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> ad_group = get_ad_group(conn, 'saradavisreports')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)
    properties = utils.safe_str_or_list(properties)
    search_base = utils.safe_dn(search_base)
    search_scope = utils.safe_scope(search_scope)

    # Get list of attributes to gather
    if properties == '*':
        attributes = [ldap3.ALL_ATTRIBUTES]
    else:
        attributes = utils.convert_to_lowercase_list(
            base=['groupType', 'name', 'sAMAccountName', 'objectSid', 'member'],
            combine_with=properties
        )

    # Get the group object(s)
    return core.get_ad_object(
        connection=connection,
        search_filter=identity.search_filter,
        properties=attributes,
        search_base=search_base,
        search_scope=search_scope
    )

# </get_ad_group>

# <move_ad_group>
def move_ad_group(connection,
                  identity,
                  new_path):
    """
    The ``move_ad_group`` function moves a group from one container to
    another.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory group object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    new_path : str
        Specifies the distinguished name of the Active Directory path to
        move the group to.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and moves the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import move_ad_group
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> move_ad_group(conn, 'saradavisreports', 'OU=Groups,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)
    new_path = utils.safe_dn(new_path)

    # Get the group account
    group = get_ad_group(connection=connection, identity=identity)
    if not group:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a group matching %s" % str(identity))

    # Move the group account
    core.move_ad_object(
        connection=connection,
        path=group[0].path,
        new_path=new_path
    )

# </move_ad_group>

# <new_ad_group>
def new_ad_group(connection,
                 name,
                 path=None,
                 attributes=None,
                 group_scope=GRP_SCOPE_GLOBAL):
    """
    The ``new_ad_group`` function creates a new Active Directory group.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    name : str
        Specifies the name of the new group. By default this parameter
        sets the ``cn``, ``name`, and ``sAMAccountName`` of the new
        group. To set different values for these properties use the
        ``attributes`` parameter.

    path : str
        [Optional] Specifies the distinguished name of the Active
        Directory path to create the group in. If not specified, groups
        are created in the Users container.

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    group_scope : admgmt constant
        [Optional]  Specifies the group scope of the new Active
        Directory group. Possible values for this parameter are defined
        in ``admgmt`` and are GRP_SCOPE_GLOBAL, GRP_SCOPE_LOCAL, or
        GRP_SCOPE_UNIVERSAL.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and creates the specified group::

        >>> from admgmt import new_ad_connection, AD_OBJ_GROUP
        >>> from admgmt.group import new_ad_group
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> new_ad_group(conn, 'saradavisreports')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    name = utils.safe_str(name)
    path = utils.safe_dn(path)
    attributes = utils.safe_dict(attributes)
    group_scope = utils.safe_group_scope(group_scope)

    # Apply a default path if none specified
    if not path:
        path = "CN=Users,%s" % connection.domain_dn

    # Put together group distinguished name
    group_dn = "CN=%s,%s" % (name, path)

    # Combine the defaults with the specified attributes
    settings = utils.convert_to_lowercase_dict(
        base={
            'cn': name,
            'groupType': GRP_SECURITY | group_scope,
            'name': name,
            'sAMAccountName': name},
        combine_with=attributes
    )

    # Create group
    core.new_ad_object(
        connection=connection,
        path=group_dn,
        obj_type=AD_OBJ_GROUP,
        attributes=settings
    )

# </new_ad_group>

# <remove_ad_group>
def remove_ad_group(connection,
                    identity):
    """
    The ``remove_ad_group`` function removes an Active Directory group.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory group object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and removes the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import remove_ad_group
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> remove_ad_group(conn, 'saradavisreports')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)

    # Get the group account
    group = get_ad_group(connection=connection, identity=identity)
    if not group:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a group matching %s" % str(identity))

    # Remove the group account
    core.remove_ad_object(
        connection=connection,
        path=group[0].path
    )

# </remove_ad_group>

# <remove_ad_group_member>
def remove_ad_group_member(connection,
                           identity,
                           remove_user=None,
                           remove_group=None,
                           remove_computer=None):
    """
    The ``remove_ad_group_member`` function removes one or more users,
    groups, service accounts, or computers as new members of an
    Active Directory group.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory group object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    remove_user : str or list
        [Optional] Specifies one or more Active Directory user objects
        to remove by providing one of the following property values.
        The identifier in parentheses is the LDAP display name for the
        attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    remove_group : str or list
        [Optional] Specifies one or more Active Directory group objects
        to remove by providing one of the following property values.
        The identifier in parentheses is the LDAP display name for the
        attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=SaraDavisReports,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

    remove_computer : str or list
        [Optional] Specifies one or more Active Directory computer
        objects to remove by providing one of the following property
        values. The identifier in parentheses is the LDAP display name
        for the attribute.

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
    Create a new connection object and removes a member from the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import remove_ad_group_member
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> remove_ad_group_member(conn, 'saradavisreports', 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)
    remove_user = utils.safe_str_or_list(remove_user)
    remove_group = utils.safe_str_or_list(remove_group)
    remove_computer = utils.safe_str_or_list(remove_computer)

    # Get the group account
    group = get_ad_group(connection=connection, identity=identity, properties=['member'])
    if not group:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a group matching %s" % str(identity))

    # Initalize the remove list and get the current member list
    remove_list = []
    if group[0]['member']:
        current_list = utils.convert_to_lowercase_list(group[0]['member'])
    else:
        current_list = []

    # Get users to remove
    for user_identity in remove_user:
        remove_list.extend(user.get_ad_user(
            connection=connection,
            identity=user_identity))

    # Get groups to remove
    for group_identity in remove_group:
        remove_list.extend(get_ad_group(
            connection=connection,
            identity=group_identity))

    # Get computers to remove
    for computer_identity in remove_computer:
        remove_list.extend(computer.get_ad_computer(
            connection=connection,
            identity=computer_identity))

    # Put the new member list together
    new_list = copy.copy(current_list)
    for ad_obj in remove_list:
        if ad_obj.path.lower() in new_list:
            new_list.remove(ad_obj.path.lower())

    # Remove group members
    if new_list != current_list:
        core.set_ad_object(
            connection=connection,
            path=group[0].path,
            attributes={'member': new_list}
        )

# </remove_ad_group_member>

# <set_ad_group>
def set_ad_group(connection,
                 identity,
                 attributes=None,
                 new_name=None):
    """Modifes the settings of an Active Directory group.

    The ``set_ad_group`` function modifies the attributes of an Active
    Directory group.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory group object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        Distinguished Name (distinguishedName), example:
            "CN=SaraDavisReports,CN=Users,DC=contoso,DC=com"

        GUID (objectGUID), example:
            "599c3d2e-f72d-4d20-8a88-030d99495f20"

        Security Identifier (objectSid), example:
            "S-1-5-21-3165297888-301567370-576410423-1103"

        SAM account name (sAMAccountName), example:
            "saradavisreports"

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    new_name : str
        [Optional] Specifies a new name for the group. By default this
        parameter sets the ``cn`` and the ``sAMAccountName`` of the
        group. To set different values for these properties use the
        ``attributes`` parameter.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and modifies the specified group::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.group import set_ad_group
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_group(conn, 'saradavisreports', {'description': "Sara's Reports"})
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_GROUP, identity)
    attributes = utils.safe_dict(attributes)
    new_name = utils.safe_str(new_name)

    # Get the group account
    group = get_ad_group(connection=connection, identity=identity)
    if not group:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a group matching %s" % str(identity))

    # Get the DN of the group
    group_dn = group[0].path

    # Change name, if specified
    if new_name:
        # Rename group
        group_new_rdn = "CN=%s" % (ldap3.utils.dn.escape_attribute_value(new_name))
        group_new_dn = "%s,%s" % (group_new_rdn, group[0].container)
        core.rename_ad_object(
            connection=connection,
            path=group_dn,
            new_relpath=group_new_rdn
        )
        group_dn = group_new_dn

        # Get the rest of the changes
        changes = utils.convert_to_lowercase_dict(
            base={'sAMAccountName': new_name},
            combine_with=attributes
        )
    elif attributes:
        # Get the changes from attributes
        changes = utils.convert_to_lowercase_dict(attributes)
    else:
        changes = None

    # Apply the changes
    if changes:
        core.set_ad_object(
            connection=connection,
            path=group_dn,
            attributes=changes
        )

# </set_ad_group>
