"""
.. module:: ou

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
import ldap3
import ldap3.utils.dn
# Module
from . import core
from . import utils

# ADObjectType Constant
AD_OBJ_OU = core.ADObjectType(
    base_filter='(&(objectCategory=organizationalUnit){})',
    ldap_class=['top', 'organizationalUnit'],
    ldap_category='CN=Organizational-Unit,CN=Schema,CN=Configuration,{}')

# <get_ad_ou>
def get_ad_ou(connection,
              identity=None,
              properties=None,
              search_base=None,
              search_scope=core.SCOPE_SUBTREE):
    """
    The ``get_ad_ou`` function gets one or more Active Directory
    OUs by performing a search against Active Directory using ldap.

    This function gets a default set of Active Directory object
    properties. To get additional properties use the ``properties``
    parameter.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        [Optional] Specifies an Active Directory OU object by
        providing one of the following property values. The identifier
        in parentheses is the LDAP display name for the attribute. If
        not specified all OU objects are returned within the bounds
        of the ``search_base`` and ``search_scope`` (which by default
        would be all OUs).

        * Distinguished Name (distinguishedName), example:
          ``OU=Europe,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``

        You can also use ``identity`` to manually specify an LDAP query
        string. This supports the same functionality as the LDAP
        syntax, but take note that some additional search filters will
        be added to whatever you specify so that only OU objects are
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
    Create a new connection object and get the specified OU::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.ou import get_ad_ou
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> ad_ou = get_ad_ou(conn, 'OU=Europe,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_OU, identity)
    properties = utils.safe_str_or_list(properties)
    search_base = utils.safe_dn(search_base)
    search_scope = utils.safe_scope(search_scope)

    # Get list of attributes to gather
    if properties == '*':
        attributes = [ldap3.ALL_ATTRIBUTES]
    else:
        attributes = utils.convert_to_lowercase_list(
            base=['l', 'c', 'gPLink', 'managedBy', 'name', 'postalCode', 'st', 'street'],
            combine_with=properties
        )

    # Get the OU object(s)
    return core.get_ad_object(
        connection=connection,
        search_filter=identity.search_filter,
        properties=attributes,
        search_base=search_base,
        search_scope=search_scope
    )

# </get_ad_ou>

# <new_ad_ou>
def new_ad_ou(connection,
              name,
              path=None,
              attributes=None):
    """
    The ``new_ad_ou`` function creates a new Active Directory OU.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    name : str
        Specifies the name of the new OU. By default this parameter
        sets the ``cn``, ``displayName``, and the ``name`` of the new
        OU. To set different values for these properties use the
        ``attributes`` parameter.

    path : str
        [Optional] Specifies the distinguished name of the Active
        Directory path to create the OU in. If not specified, OUs
        are created in the root of the domain.

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
    Create a new connection object and creates the specified OU::

        >>> from admgmt import new_ad_connection, AD_OBJ_OU
        >>> from admgmt.ou import new_ad_ou
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> new_ad_ou(conn, 'France', 'OU=Europe,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    name = utils.safe_str(name)
    path = utils.safe_dn(path)
    attributes = utils.safe_dict(attributes)

    # Apply a default path if none specified
    if not path:
        path = connection.domain_dn

    # Put together OU distinguished name
    ou_dn = "OU=%s,%s" % (name, path)

    # Combine the defaults with the specified attributes
    settings = utils.convert_to_lowercase_dict(
        base={'name': name},
        combine_with=attributes
    )

    # Create ou
    core.new_ad_object(
        connection=connection,
        path=ou_dn,
        obj_type=AD_OBJ_OU,
        attributes=settings
    )

# </new_ad_ou>

# <remove_ad_ou>
def remove_ad_ou(connection,
                 identity):
    """
    The ``remove_ad_ou`` function removes an Active Directory OU.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory OU object by providing one of the
        following property values. The identifier in parentheses is the
        LDAP display name for the attribute. If not specified all OU
        objects are returned within the bounds of the ``search_base``
        and ``search_scope`` (which by default would be all OUs).

        * Distinguished Name (distinguishedName), example:
          ``OU=Europe,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and removes the specified OU::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.ou import remove_ad_ou
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> remove_ad_ou(conn, 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_OU, identity)

    # Get the OU account
    ou_obj = get_ad_ou(connection=connection, identity=identity)
    if not ou_obj:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a OU matching %s" % str(identity))

    # Remove the OU account
    core.remove_ad_object(
        connection=connection,
        path=ou_obj[0].path
    )

# </remove_ad_ou>

# <set_ad_ou>
def set_ad_ou(connection,
              identity,
              attributes=None,
              new_name=None):
    """
    The ``set_ad_ou`` function modifies the attributes of an Active
    Directory OU.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory OU object by providing one of the
        following property values. The identifier in parentheses is the
        LDAP display name for the attribute. If not specified all OU
        objects are returned within the bounds of the ``search_base``
        and ``search_scope`` (which by default would be all OUs).

        * Distinguished Name (distinguishedName), example:
          ``OU=Europe,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    new_name : str
        [Optional] Specifies a new name for the OU. By default this
        parameter sets the ``name`` of the OU. To set different values
        for these properties use the ``attributes`` parameter.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and modifies the specified OU::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.ou import set_ad_ou
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_ou(conn, 'OU=Europe,DC=contoso,DC=com', {'description': 'Europe'})
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_OU, identity)
    attributes = utils.safe_dict(attributes)
    new_name = utils.safe_str(new_name)

    # Get the OU account
    ou_obj = get_ad_ou(connection=connection, identity=identity)
    if not ou_obj:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a OU matching %s" % str(identity))

    # Get the DN of the ou
    ou_dn = ou_obj[0].path

    # Gather the changes
    if new_name:
        # Rename ou
        ou_new_rdn = "OU=%s" % (ldap3.utils.dn.escape_attribute_value(new_name))
        ou_new_dn = "%s,%s" % (ou_new_rdn, ou_obj[0].container)
        core.rename_ad_object(
            connection=connection,
            path=ou_dn,
            new_relpath=ou_new_rdn
        )
        ou_dn = ou_new_dn

        # Combine the new_name changes with attributes
        changes = utils.convert_to_lowercase_dict(
            base={'name': new_name},
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
            path=ou_dn,
            attributes=changes
        )

# </set_ad_ou>
