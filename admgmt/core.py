"""
.. module:: container

.. TODO:
    * figure out a way to make dn searches more direct
    * investigate a better way to alert on failed operations
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
import re
import uuid
# Third party
import ldap3
import ldap3.utils.conv
import ldap3.utils.dn
# Package
from . import utils

# LDAP Search Constants
SCOPE_BASE = ldap3.BASE
SCOPE_LEVEL = ldap3.LEVEL
SCOPE_SUBTREE = ldap3.SUBTREE

# User Account Control Constants
UAC_SCRIPT = 1
UAC_ACCOUNTDISABLE = 2
UAC_HOMEDIR_REQUIRED = 8
UAC_LOCKOUT = 16
UAC_PASSWD_NOTREQD = 32
UAC_PASSWD_CANT_CHANGE = 64
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 128
UAC_TEMP_DUPLICATE_ACCOUNT = 256
UAC_NORMAL_ACCOUNT = 512
UAC_INTERDOMAIN_TRUST_ACCOUNT = 2048
UAC_WORKSTATION_TRUST_ACCOUNT = 4096
UAC_SERVER_TRUST_ACCOUNT = 8192
UAC_DONT_EXPIRE_PASSWORD = 65536
UAC_MNS_LOGON_ACCOUNT = 131072
UAC_SMARTCARD_REQUIRED = 262144
UAC_TRUSTED_FOR_DELEGATION = 524288
UAC_NOT_DELEGATED = 1048576
UAC_USE_DES_KEY_ONLY = 2097152
UAC_DONT_REQ_PREAUTH = 4194304
UAC_PASSWORD_EXPIRED = 8388608
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216
UAC_PARTIAL_SECRETS_ACCOUNT = 67108864

# <ADIdentity>
class ADIdentity(object):
    """
    Instances of this class are created by object type specific
    submodules (such as ``admgmt.user`` or ``admgmt.group``) to
    describe the identity of one or more objects and then pass that
    information along to other functions. Ultimately this information
    is used to generate the ``search_filter`` for use with
    ``get_ad_object``.

    Parameters
    ----------
    obj_type : ADObjectType
        Specifies the object type to create. Possible values are
        defined in ``admgmt`` and are AD_OBJ_USER, AD_OBJ_CONTACT,
        AD_OBJ_COMPUTER, AD_OBJ_GROUP, AD_OBJ_OU, or AD_OBJ_CONTAINER

    identity : str
        Specifies an Active Directory object by providing an property
        value that identifies the object. The property values vary by
        ``obj_type``, but generally are one of the following.

        * Distinguished Name (distinguishedName), example:
          ``CN=Davis\\, Sara,CN=Users,DC=contoso,DC=com``
        * GUID (objectGUID), example:
          ``599c3d2e-f72d-4d20-8a88-030d99495f20``
        * Security Identifier (objectSid), example:
          ``S-1-5-21-3165297888-301567370-576410423-1103``
        * SAM account name (sAMAccountName), example:
          ``saradavisreports``

        Depending on the use case sometimes ``identity`` may also be
        used to manually specify an LDAP query string. This supports
        the same functionality as the LDAP syntax, but take note that
        some additional search filters may be added to select only the
        specified objects described by obj_type.

    Attributes
    ----------
    identity : str
        Contains the str specified by the ``identity`` parameter.

    obj_type : ADObjectType
        Contains the ADObjectType specified by the ``obj_type``
        parameter.
    """
    def __init__(self, obj_type, identity=None):
        # Validate parameters
        if identity and not isinstance(identity, (str, unicode)):
            raise TypeError('identity must be specified as a str')
        if not isinstance(obj_type, ADObjectType):
            raise TypeError('obj_type must be specified as an ADObjectType')

        # Initalize properties
        self.obj_type = obj_type
        if identity:
            self.identity = identity
        else:
            self.identity = ""

    def __repr__(self):
        return self.search_filter

    def get_ldap_category(self, domain_dn):
        """Gets the objectCategory of the identity for use when
        creating a new object"""
        return self.obj_type.get_ldap_category(domain_dn)

    @property
    def ldap_class(self):
        """The objectClass list of the identity for use when creating a
        new object."""
        return self.obj_type.ldap_class

    @property
    def search_filter(self):
        """The ldap search filter used to select the the identity"""
        return self.obj_type.get_search_filter(self.identity)

# </ADIdentity>

# <ADObject>
class ADObject(object):
    """
    Instances of this class are created by ``get_ad_object`` and are
    used to describe the Active Directory objects gathered.

    Parameters
    ----------
    attributes : CaseInsensitiveDict, Entrydict, or dict
        Specifies the object attributes and values gathered by
        the results of an ldap search.

    Attributes
    ----------
    attributes : CaseInsensitiveDict
        A CaseInsensitiveDict containing the details information
        specified by the ``attributes`` parameter.
    """
    def __init__(self, attributes):
        if isinstance(attributes, ldap3.utils.ciDict.CaseInsensitiveDict):
            self.attributes = attributes
        elif isinstance(attributes, ldap3.abstract.entry.Entry):
            self.attributes = ldap3.utils.ciDict.CaseInsensitiveDict()
            for key in attributes.entry_get_attribute_names():
                self.attributes[key] = attributes[key].value
        elif isinstance(attributes, dict):
            self.attributes = ldap3.utils.ciDict.CaseInsensitiveDict(attributes)

    def __repr__(self):
        return "ADObject('%s')" % self.path

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    @property
    def path(self):
        """The distinguished name of the Active Directory object."""
        return self.attributes['distinguishedName']

    @property
    def relpath(self):
        """The distinguished name relative to the container holding the
        Active Directory object."""
        return ldap3.utils.dn.safe_rdn(self.path)[0]

    @property
    def container(self):
        """The path to the container holding the Active Directory
        object."""
        return self.path.replace("%s," % self.relpath, "")

    @property
    def guid(self):
        """The GUID of the Active Directory object."""
        return self.attributes['objectGUID']
# </ADObject>

# <ADObjectType>
class ADObjectType(object):
    """
    Instances of this class are defined as constants in the applicable
    type specific module. These instances are use to describe various
    Active Directory object types (Users, Computers, etc.).

    Parameters
    ----------
    base_filter : str
        The base filter template to use when searching for objects of
        this type. This template should include a single bracket ``{}``
        for use with ``get_search_filter`` to designate the location to
        insert additional search filters into.

        * Example:
          ``(&(objectCategory=person)(objectClass=user){})``

    ldap_class : list
        A list of classes describing the Active Directory object. These
        are the values that will be set to the objectClass property on
        new objects of this type.

        * Example:
          ``['top', 'person', 'organizationalPerson', 'user']``

    ldap_categroy : str
        The ldap_category template should be the distinguished name of
        the objectCategory property to be set on new objects of this
        type. This template should include a single bracket {} where
        the distinguished name of the domain should go.

        * Example:
          ``CN=Person,CN=Schema,CN=Configuration,{}``

    def_id_filter: str
        [Optional] The def_id_filter template should be ldap search
        query to use if another identity couldn't be matched. Primarily
        this is use to identify object types that use sAMAccountName as
        all the other identifiers are easy to detect. This template
        should include a single bracket {} where the identity should be
        placed in the search query.

        * Example:
          ``(sAMAccountName={})``

    Attributes
    ----------
    ldap_class : str
        Contains the str specified by the ``ldap_class`` parameter.
    """
    def __init__(self, base_filter, ldap_class, ldap_category, def_id_filter=None):
        # Validate parameters
        if (base_filter and
                not isinstance(base_filter, list) and
                any(not isinstance(item, (str, unicode)) for item in base_filter)):
            raise TypeError('base_filter, if specified, must be a list of all strings')
        if (ldap_class and
                not isinstance(ldap_class, list) and
                any(not isinstance(item, (str, unicode)) for item in ldap_class)):
            raise TypeError('ldap_class, if specified, must be a list of all strings')
        if (ldap_class and
                not isinstance(ldap_category, (str, unicode))):
            raise TypeError('ldap_category, if specified, must be a str')
        if (def_id_filter and
                not isinstance(def_id_filter, (str, unicode))):
            raise TypeError('def_id_filter, if specified, must be a str')

        # Initalize parameters
        self.ldap_class = ldap_class
        self._base_filter = base_filter
        self._ldap_category = ldap_category
        self._def_id_filter = def_id_filter

    def get_search_filter(self, identity=None):
        """Get a ldap search filter to use with ``get_ad_object``"""
        # Validate identity
        if identity and not isinstance(identity, (str, unicode)):
            raise TypeError('identity must be specified as a str')

        # Get identity specific search string
        if identity:
            # ldap filter
            if identity.startswith('(') and identity.endswith(')'):
                identity_filter = identity
            # distinguishedName
            elif re.search('^(CN=|OU=|DC=)', identity, re.IGNORECASE):
                identity_filter = "(distinguishedName=%s)" % identity
            # objectGUID
            elif re.search('^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-z]{12}$', identity, re.IGNORECASE):
                identity_filter = "(objectGUID=%s)" % ldap3.utils.conv.escape_bytes(
                    bytes_value=uuid.UUID(hex=identity).bytes)
            # objectSid
            elif identity.startswith('S-1-5-21-'):
                identity_filter = "(objectSid=%s)" % identity
            # userPrincipalName
            elif "@" in identity:
                identity_filter = "(userPrincipalName=%s)" % identity
            # default identity
            elif self._def_id_filter:
                # set default identity, removing any trialing $ signs
                identity_filter = self._def_id_filter.format(re.sub(r'\$*$', '', identity))
            # unknown
            else:
                raise ValueError('Unsupported or unknown identity type')

            return self._base_filter.format(identity_filter)
        else:
            return self._base_filter.format("")

    def get_ldap_category(self, domain_dn):
        """Get a ldap objectCategory for use with ``new_ad_object``"""
        return self._ldap_category.format(domain_dn)

# </ADObjectType>

# <get_ad_object>
def get_ad_object(connection,
                  search_filter,
                  properties=None,
                  search_base=None,
                  search_scope=SCOPE_SUBTREE):
    """
    The ``get_ad_object`` function gets one or more Active Directory
    objects by performing a search against Active Directory using ldap.

    This function gets a default set of Active Directory object
    properties. To get additional properties use the ``properties``
    parameter.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    search_filter : str
        Specifies an LDAP query string that is used to filter Active
        Directory objects. Supports the same functionality as the LDAP
        syntax.

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
    Create a new connection object and get the specified object::

    >>> from admgmt import new_ad_connection
    >>> from admgmt.core import get_ad_object
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> ad_obj = get_ad_object(conn, 'CN=User1,CN=Users,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    search_filter = utils.safe_str(search_filter)
    properties = utils.safe_str_or_list(properties)
    search_base = utils.safe_dn(search_base)
    search_scope = utils.safe_scope(search_scope)

    # Get a default search_base if necessary
    if not search_base:
        search_base = connection.domain_dn

    # Get list of attributes to gather
    if properties == '*':
        attributes = [ldap3.ALL_ATTRIBUTES]
    else:
        attributes = utils.convert_to_lowercase_list(
            base=['distinguishedName', 'objectClass', 'objectGUID'],
            combine_with=properties
        )

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    # Process the search
    try:
        # Kick off the search
        entry_generator = connection.ldap.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
            paged_size=100,
            generator=True
        )

        # Process the results
        results = []
        for entry in entry_generator:
            if entry['type'] == 'searchResEntry':
                results.append(ADObject(entry['attributes']))
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()

    # Return the results
    if results:
        return results
    else:
        return None

# </get_ad_object>

# <move_ad_object>
def move_ad_object(connection,
                   path,
                   new_path):
    """
    The ``move_ad_object`` function moves an object or a container of
    objects from one container to another.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to move.

    new_path : str
        Specifies the distinguished name of the Active Directory path to
        move the object to.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and moves the specified object::

    >>> from admgmt import new_ad_connection
    >>> from admgmt.core import move_ad_object
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> move_ad_object(conn, 'CN=Group1,CN=Users,DC=contoso,DC=com', 'OU=Groups,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)
    new_path = utils.safe_dn(new_path)

    # Get the relative distinguished name
    relpath = utils.safe_rdn(path)

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    try:
        # Create the object
        connection.ldap.modify_dn(dn=path, relative_dn=relpath, new_superior=new_path)
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()

# </move_ad_object>

# <new_ad_object>
def new_ad_object(connection,
                  path,
                  obj_type,
                  attributes=None):
    """
    The ``new_ad_object`` function creates a new Active Directory
    object such as a new organizational unit or new user account. You
    can use this cmdlet to create any type of Active Directory object.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to create.

    obj_type : admgmt constant
        Specifies the object type to create. Possible values are
        defined in ``admgmt`` and are AD_OBJ_USER, AD_OBJ_CONTACT,
        AD_OBJ_COMPUTER, AD_OBJ_GROUP, AD_OBJ_OU, or AD_OBJ_CONTAINER

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
    Create a new connection object and creates the specified object::

    >>> from admgmt import new_ad_connection, AD_OBJ_USER
    >>> from admgmt.core import new_ad_object
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> new_ad_object(conn, 'CN=User1,CN=Users,DC=contoso,DC=com', AD_OBJ_USER)
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)
    obj_type = utils.safe_ad_obj_type(obj_type)
    attributes = utils.safe_dict(attributes)

    # Process settings to gather the specified attributes
    settings = {}
    if attributes:
        for key, value in attributes.items():
            settings[key.lower()] = value

    # Add the object type to the attributes
    settings['objectclass'] = obj_type.ldap_class

    # Add the object class to the attributes
    settings['objectcategory'] = obj_type.get_ldap_category(connection.domain_dn)

    # Pull together sam value for existance check
    if settings.has_key('samaccountname'):
        sam = settings['samaccountname']
    else:
        sam = None

    # Pull together upn value for existance check
    if settings.has_key('userprincipalname'):
        upn = settings['userprincipalname']
    else:
        upn = None

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    try:
        # Verify user_dn, sAMAccountName, and userPrincipalName
        found = test_ad_object(connection=connection, path=path, sam=sam, upn=upn)
        if found:
            raise ldap3.LDAPEntryAlreadyExistsResult(" AND ".join(found))

        # Create the object
        connection.ldap.add(dn=path, attributes=settings)
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()

# </new_ad_object>

# <remove_ad_object>
def remove_ad_object(connection,
                     path):
    """
    The ``remove_ad_object`` function removes an Active Directory
    object. You can use this function to remove any type of Active
    Directory object.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to remove.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and removes the specified object::

    >>> from admgmt import new_ad_connection
    >>> from admgmt.core import remove_ad_object
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> remove_ad_object(conn, 'CN=Group1,CN=Users,DC=contoso,DC=com')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    try:
        # Remove the object
        connection.ldap.delete(dn=path)
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()

# </remove_ad_object>

# <rename_ad_object>
def rename_ad_object(connection,
                     path,
                     new_relpath):
    """
    The ``rename_ad_object`` function renames an Active Directory
    object. This cmdlet sets the ``name`` property of an Active
    Directory object that has an ldapDisplayName of "name". To modify
    the given name, surname and other name of an object, use the
    ``set_ad_object`` function.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to rename.

    new_rdn : str
        Specifies the new relative distinguished name of the Active
        Directory.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and renames the specified object::

    >>> from admgmt import new_ad_connection
    >>> from admgmt.core import rename_ad_object
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> rename_ad_object(conn, 'CN=Group1,CN=Users,DC=contoso,DC=com', 'CN=GroupA')
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)
    new_relpath = utils.safe_rdn(new_relpath)

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    try:
        # Create the object
        connection.ldap.modify_dn(dn=path, relative_dn=new_relpath)
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()

# </rename_ad_object>

# <set_ad_object>
def set_ad_object(connection,
                  path,
                  attributes):
    """
    The ``set_ad_object`` function modifies the attributes of an Active
    Directory object.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to change.

    attributes : dict
        Specifies object attribute values for attributes. You can set
        one or more parameters at the same time with this parameter. If
        an attribute takes more than one value, you can assign multiple
        values as a list. To identify an attribute, specify the key
        using the ldapDisplayName as defined for it in the Active
        Directory schema.

    Returns
    -------
    None

    Examples
    --------
    Create a new connection object and modifies the specified object::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.core import set_ad_object
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> set_ad_object(conn, 'CN=Group1,CN=Users,DC=contoso,DC=com', {'description': 'Test'})
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)
    attributes = utils.safe_dict(attributes)

    # Put together the changes
    changes = {}
    for key, value in attributes.items():
        if isinstance(value, list):
            changes[key] = [(ldap3.MODIFY_REPLACE, value)]
        else:
            changes[key] = [(ldap3.MODIFY_REPLACE, [value])]

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    try:
        # Create the object
        connection.ldap.modify(dn=path, changes=changes)
    finally:
        # Disconnect from Active Directory
        if not was_bound:
            connection.unbind()


# </set_ad_object>

# <test_ad_object>
def test_ad_object(connection,
                   path=None,
                   sam=None,
                   upn=None):
    """
    The ``test_ad_object`` function determines whether any Active
    Directory objects exist that match the provided parameters.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    path : str
        Specifies the distinguished name of an Active Directory object
        to check exists.

    sam : str
        Specifies the sam account name of an Active Directory object to
        check exists.

    upn : str
        Specifies the user principal name of an Active Directory object
        to check exists.

    Returns
    -------
    list
        A list of messages identifying which parameter matches
        objects that already exist.

    Examples
    --------
    Create a new connection object and modifies the specified object::

        >>> from admgmt import new_ad_connection
        >>> from admgmt.core import test_ad_object
        >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
        >>> test_ad_object(conn, 'CN=Group1,CN=Users,DC=contoso,DC=com')
        ["The distinguishedName 'CN=Group1,CN=Users,DC=contoso,DC=com' already exists"]
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    path = utils.safe_dn(path)
    sam = utils.safe_str(sam)
    upn = utils.safe_str(upn)

    # Connect to Active Directory
    was_bound = connection.bound
    connection.bind()

    # Put the checks together
    check = {}
    if path:
        check['distinguishedName'] = path
    if sam:
        check['sAMAccountName'] = sam
    if upn:
        check['userPrincipalName'] = upn

    # Perform the checks
    found = []
    for key, value in check.items():
        # Get the search filter
        search_filter = "({}={})".format(key, value)

        # Check for the object
        if get_ad_object(connection=connection, search_filter=search_filter):
            found.append(
                "The %s '%s' already exists" % (key, value)
            )

    # Disconnect from Active Directory
    if not was_bound:
        connection.unbind()

    # Return the results
    return found

# </test_ad_object>
