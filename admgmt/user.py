"""
.. module:: user

.. TODO:
    * Validate functions
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
AD_OBJ_USER = core.ADObjectType(
    base_filter='(&(objectCategory=person)(objectClass=user){})',
    ldap_class=['top', 'person', 'organizationalPerson', 'user'],
    ldap_category='CN=Person,CN=Schema,CN=Configuration,{}',
    def_id_filter='(sAMAccountName={})')

# <get_ad_user>
def get_ad_user(connection,
                identity=None,
                properties=None,
                search_base=None,
                search_scope=core.SCOPE_SUBTREE):
    """
    The ``get_ad_user`` function gets one or more Active Directory
    users by performing a search against Active Directory using ldap.

    This function gets a default set of Active Directory object
    properties. To get additional properties use the ``properties``
    parameter.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        [Optional] Specifies an Active Directory user object by
        providing one of the following property values. The identifier
        in parentheses is the LDAP display name for the attribute. If
        not specified all user objects are returned within the bounds
        of the ``search_base`` and ``search_scope`` (which by default
        would be all users).

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

        You can also use ``identity`` to manually specify an LDAP query
        string. This supports the same functionality as the LDAP
        syntax, but take note that some additional search filters will
        be added to whatever you specify so that only user objects are
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
    Create a new connection object and get the specified user::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.user import get_ad_user
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> ad_user = get_ad_user(conn, 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_USER, identity)
    properties = utils.safe_str_or_list(properties)
    search_base = utils.safe_dn(search_base)
    search_scope = utils.safe_scope(search_scope)

    # Get list of attributes to gather
    if properties == '*':
        attributes = [ldap3.ALL_ATTRIBUTES]
    else:
        attributes = utils.convert_to_lowercase_list(
            base=['givenName', 'name', 'objectSid', 'sAMAccountName', 'sn', 'userPrincipalName'],
            combine_with=properties
        )

    # Get the user object(s)
    return core.get_ad_object(
        connection=connection,
        search_filter=identity.search_filter,
        properties=attributes,
        search_base=search_base,
        search_scope=search_scope
    )

# </get_ad_user>

# <move_ad_user>
def move_ad_user(connection,
                 identity,
                 new_path):
    """
    The ``move_ad_user`` function moves a user from one container to
    another.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory user object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    new_path : str
        Specifies the distinguished name of the Active Directory path to
        move the user to.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and moves the specified user::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.user import move_ad_user
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> move_ad_user(conn, 'sadavi', 'OU=Accounts,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_USER, identity)
    new_path = utils.safe_dn(new_path)

    # Get the user account
    user = get_ad_user(connection=connection, identity=identity)
    if not user:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a user matching %s" % str(identity))

    # Move the user account
    core.move_ad_object(
        connection=connection,
        path=user[0].path,
        new_path=new_path
    )

# </move_ad_user>

# <new_ad_user>
def new_ad_user(connection,
                name,
                username,
                path=None,
                attributes=None):
    """
    The ``new_ad_user`` function creates a new Active Directory user.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    name : str
        Specifies the name of the new user. By default this parameter
        sets the ``cn``, ``displayName``, and the ``name`` of the new
        user. To set different values for these properties use the
        ``attributes`` parameter.

    username : str
        Specifies the username of the new user. By default this
        parameter sets both the ``sAMAccountName`` and
        ``userPrincipalName`` of the new user. The
        ``userPrincipalName`` will, by default, use the domain
        specified by the ``connection`` object.

        To set different values for these properties use the
        ``attributes`` parameter.

    path : str
        [Optional] Specifies the distinguished name of the Active
        Directory path to create the user in. If not specified, users
        are created in the Users container.

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
    Create a new connection object and creates the specified user::

        >>> from admgmt import new_ad_connection, AD_OBJ_USER
        >>> from admgmt.user import new_ad_user
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> new_ad_user(conn, 'Davis, Sara', 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    name = utils.safe_str(name)
    username = utils.safe_str(username)
    path = utils.safe_dn(path)
    attributes = utils.safe_dict(attributes)

    # Apply a default path if none specified
    if not path:
        path = "CN=Users,%s" % connection.domain_dn

    # Put together user distinguished name
    user_dn = "CN=%s,%s" % (name, path)

    # Combine the defaults with the specified attributes
    settings = utils.convert_to_lowercase_dict(
        base={
            'cn': name,
            'displayName': name,
            'name': name,
            'sAMAccountName': username,
            'userAccountControl': str(
                core.UAC_NORMAL_ACCOUNT + core.UAC_ACCOUNTDISABLE),
            'userPrincipalName': "%s@%s" % (username, connection.domain)},
        combine_with=attributes
    )

    # Create User
    core.new_ad_object(
        connection=connection,
        path=user_dn,
        obj_type=AD_OBJ_USER,
        attributes=settings
    )

# </new_ad_user>

# <remove_ad_user>
def remove_ad_user(connection,
                   identity):
    """
    The ``remove_ad_user`` function removes an Active Directory user.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory user object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and removes the specified user::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.user import remove_ad_user
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> remove_ad_user(conn, 'sadavi')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_USER, identity)

    # Get the user account
    user = get_ad_user(connection=connection, identity=identity)
    if not user:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a user matching %s" % str(identity))

    # Remove the user account
    core.remove_ad_object(
        connection=connection,
        path=user[0].path
    )

# </remove_ad_user>

# <set_ad_user>
def set_ad_user(connection,
                identity,
                attributes=None,
                new_name=None,
                new_username=None):
    """
    The ``set_ad_user`` function modifies the attributes of an Active
    Directory user.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory user object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    attributes : dict
        [Optional] Specifies object attribute values for attributes.
        You can set one or more parameters at the same time with this
        parameter. If an attribute takes more than one value, you can
        assign multiple values as a list. To identify an attribute,
        specify the key using the ldapDisplayName as defined for it in
        the Active Directory schema.

    new_name : str
        [Optional] Specifies a new name for the user. By default this
        parameter sets the ``cn``, ``displayName``, and the ``name`` of
        the user. To set different values for these properties use the
        ``attributes`` parameter.

    new_username : str
        [Optional] Specifies a new username for the user. By default
        this parameter sets both the ``sAMAccountName`` and
        ``userPrincipalName`` of the user. The ``userPrincipalName``
        will, by default, use the domain specified by the
        ``connection`` object.

        To set different values for these properties use the
        ``attributes`` parameter.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and modifies the specified user::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.user import set_ad_user
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_user(conn, 'sadavi', {'company': 'Contoso'})
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_USER, identity)
    attributes = utils.safe_dict(attributes)
    new_name = utils.safe_str(new_name)
    new_username = utils.safe_str(new_username)

    # Get the user account
    user = get_ad_user(connection=connection, identity=identity)
    if not user:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a user matching %s" % str(identity))

    # Get the DN of the user
    user_dn = user[0].path

    # Gather the changes
    if new_name:
        # Rename user
        user_new_rdn = "CN=%s" % (ldap3.utils.dn.escape_attribute_value(new_name))
        user_new_dn = "%s,%s" % (user_new_rdn, user[0].container)
        core.rename_ad_object(
            connection=connection,
            path=user_dn,
            new_relpath=user_new_rdn
        )
        user_dn = user_new_dn

        # Combine the new_name and new_username changes with attributes
        if new_username:
            changes = utils.convert_to_lowercase_dict(
                base={
                    'displayName': new_name,
                    'sAMAccountName': new_username,
                    'userPrincipalName': "%s@%s" % (new_username, connection.domain)},
                combine_with=attributes
            )
        # Combine the new_name changes with attributes
        else:
            changes = utils.convert_to_lowercase_dict(
                base={'displayName': new_name},
                combine_with=attributes
            )
    elif new_username:
        # Combine the changes from new_username and attributes
        changes = utils.convert_to_lowercase_dict(
            base={
                'sAMAccountName': new_username,
                'userPrincipalName': "%s@%s" % (new_username, connection.domain)},
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
            path=user_dn,
            attributes=changes
        )

# </set_ad_user>

# <set_ad_user_password>
def set_ad_user_password(connection,
                         identity,
                         new_password):
    """
    The ``set_ad_user_password`` function sets the password of an
    Active Directory user. If the account is disabled it will also
    enable the account as part of the operation.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    identity : str
        Specifies an Active Directory user object by providing one of
        the following property values. The identifier in parentheses is
        the LDAP display name for the attribute.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``sadavi``

    new_password : str
        Specifies the new pasword for the user.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and sets the password on the specified user::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.user import set_ad_user_password
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_user_password(conn, 'sadavi', 'newP@ssw0rd')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    identity = utils.safe_identity(AD_OBJ_USER, identity)
    new_password = utils.safe_str(new_password)

    # Get the user account
    user = get_ad_user(connection=connection, identity=identity, properties=['userAccountControl'])
    if not user:
        raise ldap3.LDAPNoSuchObjectResult("Cannot find a user matching %s" % str(identity))

    # Encode the password
    changes = {}
    unicode_pass = unicode('\"' + new_password + '\"', 'iso-8859-1')
    encoded_pass = unicode_pass.encode('utf-16-le')
    changes['unicodePwd'] = encoded_pass

    # Enable the account, if disabled
    user_uac = int(user[0]['userAccountControl'])
    if user_uac & core.UAC_ACCOUNTDISABLE > 0:
        changes['userAccountControl'] = str(user_uac ^ core.UAC_ACCOUNTDISABLE)

    # Make the changes
    core.set_ad_object(
        connection=connection,
        path=user[0].path,
        attributes=changes
    )

# </set_ad_user_password>
