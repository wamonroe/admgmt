"""
.. module:: utils

.. TODO:
    * make a selective safe_identity
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
import socket
# Third party
import ldap3
import ldap3.utils.dn
# Package
# Note: Most of the various modules that make up the admgmt package are
# heavily dependent on the generic functions of this module. Due to
# challenges with Python 2 and circular imports, the interpackage
# imports for checking constants, class types, or the like had to be
# deffered into the functions themselves.

# <convert_to_lowercase_dict>
def convert_to_lowercase_dict(base, combine_with=None):
    """
    Converts the keys of a dict to lowercase and optionally combines
    with a second dict. If a key is specified multiple times in the
    same dictionary that would result in the same lowercase key in the
    resulting dictionary (e.g. key, Key, KEy) the value used will
    be at random.

    Parameters
    ----------
    base : dict
        Specifies the base dict.

    combine_with : dict
        [Optional] Specifies the dict to combine the base dict with. If
        a key is specified that is already in the default list it will
        overwrite the value of the default in the resulting dict.

    Returns
    -------
    dict
        A dict with all lowercase keys.

    Examples
    --------
    Combines the attribute settings from the two lists, overwriting
    base values::

        >>> combine_attribute_settings({'a': 1, 'b': 2}, {'b': 3, 'c': 4})
        {'a': 1, 'b': 3, 'c': 4}
    """
    # Validate and get normalized parameters
    base = safe_dict(base)
    combine_with = safe_dict(combine_with)

    # Build the attribute settings dict
    settings = {}

    # Add the base settings
    for key, value in base.items():
        settings[key.lower()] = value

    # Add any combine_with settings
    if combine_with:
        for key, value in combine_with.items():
            settings[key.lower()] = value

    # Return results
    return settings

# </convert_to_lowercase_dict>

# <convert_to_lowercase_list>
def convert_to_lowercase_list(base, combine_with=None):
    """
    Converts a list to all lowercase values and optionally combines
    with a second list. Any duplicate values are omitted.

    Parameters
    ----------
    base : str or list
        Specifies the base list.

    combine_with : str or list
        [Optional] Specifies the list to combine the base list with.

    Returns
    -------
    list
        A list of all lowercase values.

    Examples
    --------
    Convert a single list to all lowercase values, omitting any values
    that are duplicate::

        >>> convert_to_lowercase_list(['apple','Orange','pEar','APPLE'])
        ['apple', 'orange', 'pear']

    Combine two lists converting both to lowercase values and omitting
    any values that are duplicate::

        >>> convert_to_lowercase_list(['apple','pear'], ['ORANGE', 'Apple'])
        ['apple', 'pear', 'orange']
    """
    # Validate and get normalized parameters
    base = safe_str_or_list(base)
    combine_with = safe_str_or_list(combine_with)


    # Initialize the lowercase list
    lowercase_list = []

    # Add the base list
    for item in base:
        if item.lower() not in lowercase_list:
            lowercase_list.append(item.lower())

    # Add any combine_with values
    if combine_with:
        for item in combine_with:
            if item.lower() not in lowercase_list:
                lowercase_list.append(item.lower())

    # Return results
    return lowercase_list

# </convert_to_lowercase_list>

# <safe_ad_obj_type>
def safe_ad_obj_type(obj_type=None):
    """
    Validate the provided obj_type is either SCOPE_BASE,
    SCOPE_LEVEL, or SCOPE_SUBTREE.

    Parameters
    ----------
    obj_type : ADObjectType
        [Optional] Specifies the object type to validate. If not
        specified, the function returns None.

    Returns
    -------
    ADObjectType or None
        A valid ADObjectType (or None, if obj_type was not specified).
    """
    from .core import ADObjectType

    if obj_type:
        # Validate and return
        if not isinstance(obj_type, ADObjectType):
            raise TypeError('obj_type must be specified as an ADObjectType')
        else:
            return obj_type
    else:
        return None

# </safe_ad_obj_type>

# <safe_bool>
def safe_bool(parameter):
    """
    Validate the provided parameter is an bool.

    Parameters
    ----------
    parameter : bool
        Specifies the parameter to validate.

    Returns
    -------
    bool
        A valid bool.
    """
    # Validate and return
    if isinstance(parameter, bool):
        return parameter
    else:
        raise TypeError('parameter must be an bool')

# </safe_bool>

# <safe_cert>
def safe_cert(cert=None):
    """
    Validate the provided cert is a either CERT_NONE, CERT_OPTIONAL,
    or CERT_REQUIRED.

    Parameters
    ----------
    cert : int
        [Optional] Specifies the cert to validate. Valid values are
        defined in ``admgmt`` and are CERT_NONE, CERT_OPTIONAL,
        CERT_REQUIRED

        If not specified, the function returns None.

    Returns
    -------
    int
        The int value of a valid cert type.
    """
    from . import CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED

    # Validate and return
    cert_list = [CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED]
    if cert in cert_list:
        return cert
    elif not cert:
        return None
    else:
        raise ValueError(
            'cert must be specified as either CERT_NONE, CERT_OPTIONAL, or CERT_REQUIRED'
        )

# </safe_cert>

# <safe_connection>
def safe_connection(connection):
    """
    Validate the provided connection is an ADConnection object.

    Parameters
    ----------
    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    Returns
    -------
    ADConnection
        A valid ADConnection object.
    """
    from . import ADConnection

    # Validate and return
    if isinstance(connection, ADConnection):
        return connection
    else:
        raise TypeError('parameter must be an ADConnection')

# </safe_connection>

# <safe_dict>
def safe_dict(parameter=None):
    """
    Validate that the provided parameter is a dict.

    Parameters
    ----------
    parameter : dict
        [Optional] Specifies the dict to validate. If not specified an
        empty dict is returned.

    Returns
    -------
    dict
        A valid dict (will return an empty dict if one was not
        specified).
    """
    # Validate and return
    if parameter and not isinstance(parameter, dict):
        raise TypeError('parameter must be specified as a dict')
    elif parameter:
        return parameter
    else:
        return {}

# </safe_dict>

# <safe_dn>
def safe_dn(path=None):
    """
    Validate the provided path is a valid distinguishedname

    Parameters
    ----------
    path : str or unicode
        [Optional] Specifies the distinguished name of the Active
        Directory path.

    Returns
    -------
    str or None
        A str of a valid distinguished name or None if not specified.
    """
    if path:
        # Validate dn and return
        try:
            return ldap3.utils.dn.safe_dn(path)
        except ldap3.LDAPInvalidDnError:
            raise ValueError('parameter must be a valid distinguished name')
    else:
        return None

# </safe_dn>

# <safe_group_scope>
def safe_group_scope(group_scope):
    """
    Validate the the provided parameter is either GRP_SCOPE_GLOBAL,
    GRP_SCOPE_LOCAL, or GRP_SCOPE_UNIVERSAL

    Parameters
    ----------
    group_scope : int
        Specifies the scope of an Active Directory group. Possible
        values for this parameter are defined in ``admgmt.group`` and
        are GRP_SCOPE_GLOBAL, GRP_SCOPE_LOCAL, and GRP_SCOPE_UNIVERSAL.

    Returns
    -------
    int
        The int value of a valid group scope.
    """
    from .group import GRP_SCOPE_GLOBAL, GRP_SCOPE_LOCAL, GRP_SCOPE_UNIVERSAL

    group_scope_list = [GRP_SCOPE_GLOBAL, GRP_SCOPE_LOCAL, GRP_SCOPE_UNIVERSAL]
    if group_scope in group_scope_list:
        return group_scope
    else:
        raise ValueError(
            'scope must be specified as either GRP_SCOPE_GLOBAL, SCOPE_LEVEL, or SCOPE_SUBTREE'
        )

# </safe_group_scope>

# <safe_identity>
def safe_identity(obj_type, identity=None):
    """
    Validate the provided identity based on the provided obj_type

    Parameters
    ----------
    obj_type : admgmt constant
        Specifies the object type to create. Possible values are
        defined in ``admgmt`` and are AD_OBJ_USER, AD_OBJ_CONTACT,
        AD_OBJ_COMPUTER, AD_OBJ_GROUP, AD_OBJ_OU, or AD_OBJ_CONTAINER

    identity : str
        [Optional] Specifies the identity to validate based on the
        obj_type. If identity isn't specified this generally results
        in an identity that would select all of a specified obj_type.

    Returns
    -------
    ADIdentity
        An ADIdentity object that contains information about the
        validated identity.
    """
    from .core import ADIdentity
    from .computer import AD_OBJ_COMPUTER

    # Validate obj_type
    obj_type = safe_ad_obj_type(obj_type)

    # Validate identity and return an ADIdentity object
    if identity and not isinstance(identity, (ADIdentity, str, unicode)):
        # Raise an error that we have a problem
        raise TypeError('identity must be either an ADIdentity or str')
    elif identity and isinstance(identity, ADIdentity):
        # Return existing ADIdentity (don't do anything else)
        return identity
    else:
        # Return resulting ADIdentity object
        return ADIdentity(obj_type=obj_type, identity=identity)

# </safe_identity>

# <safe_rdn>
def safe_rdn(path=None):
    """
    Validate the provided path is either a valid relative
    distinguished name or that one can be obtained by parsing the
    provided path.

    Parameters
    ----------
    path : str
        [Optional] Specifies the relative distinguished name to
        validate or the distinguished name to attempt to get the
        relative distinguished name from.

    Returns
    -------
    str or None
        A str of a valid relative distinguished name or None if not
        specified.
    """
    if path:
        # Validate path and return
        try:
            return ldap3.utils.dn.safe_rdn(path)[0]
        except ldap3.LDAPInvalidDnError:
            raise ValueError('parameter must be a valid relative distinguished name')
    else:
        return None

# </safe_rdn>

# <safe_server_list>
def safe_server_list(domain, server_list=None):
    """
    Validate that the provided server_list is either a str of a
    single server or a list of servers. If not provided, randomly
    select a server from the domain. In either case, normalize
    into a list of server names.

    Parameters
    ----------
    domain : str
        Specifies the Active Directory ``domain`` that is being
        connected to. If ``server_list`` is not specified this will be
        used to randomly select a domain controller.

    server_list : list or str
        [Optional] Specifies the list of domain controllers to
        connection to. By default one of the domain controllers are
        selected at random.

    Returns
    -------
    list
        A list of server names
    """
    # Validate and Normalize
    if not server_list:
        return [socket.gethostbyaddr(domain)[0]]
    if server_list and isinstance(server_list, (str, unicode)):
        return [server_list]
    elif server_list and isinstance(server_list, list):
        return server_list
    else:
        raise TypeError('parameter must be specified as a str or list')

# </safe_server_list>

# <safe_str_or_list>
def safe_str_or_list(parameter=None):
    """
    Validate that the provided parameter is either a str or a
    list. Normalizes a provided str into a list.

    Parameters
    ----------
    parameter : list or str
        [Optional] Specifies the list or str to validate. If a str is
        specified it will be returned as a single item list. If not
        specified an empty list is returned.

    Returns
    -------
    list
        A list of one or more valid values.
    """
    if parameter:
        # Validate
        if not isinstance(parameter, (str, unicode, list)):
            raise TypeError('parameter must be specified as a str or list')

        # Normalize
        if not isinstance(parameter, list):
            return [parameter]
        else:
            return parameter
    else:
        return []

# </safe_str_or_list>

# <safe_str>
def safe_str(parameter=None, default=""):
    """
    Validate that the provided parameter is a str.

    Parameters
    ----------
    parameter : str
        [Optional] Specifies the str to validate. If not specified a
        empty string is returned.

    default : str
        [Optional] Specifies the default str to return return if the
        parameter is not specified. This can either be a str or None.
        The default value to return is an empty string.
    Returns
    -------
    str
        A valid str (will return an empty string if one was not
        specified).
    """
    # Validate and return
    if parameter and not isinstance(parameter, (str, unicode)):
        raise TypeError('parameter must be specified as a str')
    elif parameter:
        return parameter
    else:
        return default

# </safe_str>

# <safe_scope>
def safe_scope(scope):
    """
    Validate that the provided parameter is either SCOPE_BASE,
    SCOPE_LEVEL, or SCOPE_SUBTREE.

    Parameters
    ----------
    scope : str
        Specifies the scope of an Active Directory search. Possible
        values for this parameter are defined in ``admgmt.core`` and
        are SCOPE_BASE, SCOPE_LEVEL, and SCOPE_SUBTREE.

    Returns
    -------
    str
        The str value of a valid scope.
    """
    from .core import SCOPE_BASE, SCOPE_LEVEL, SCOPE_SUBTREE

    # Validate and return
    scope_list = [SCOPE_BASE, SCOPE_LEVEL, SCOPE_SUBTREE]
    if scope in scope_list:
        return scope
    else:
        raise ValueError(
            'scope must be specified as either SCOPE_BASE, SCOPE_LEVEL, or SCOPE_SUBTREE'
        )

# </safe_scope>
