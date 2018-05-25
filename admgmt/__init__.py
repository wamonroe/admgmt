"""
TODO:

* build the following submodules:
    * contact
    * ou
    * container

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
import ssl
# Third party
import ldap3
# Module
from . import utils

# SSL Certificate Constants
CERT_NONE = ssl.CERT_NONE
CERT_OPTIONAL = ssl.CERT_OPTIONAL
CERT_REQUIRED = ssl.CERT_REQUIRED

# <ADConnection>
class ADConnection(object):
    """
    Instances of this class are created with the ``new_ad_connection``
    function and is used to describe the connection to Active
    Directory. This object is then passed among other functions for
    performing various operations again.

    Parameters
    ----------
    domain : str
        The name of the domain to connect to.

    ldap_connection : ldap3.Connection
        The ldap3 Connection object describing the connection to the
        domain.

    Attributes
    ----------
    domain : str
        Contains the str specified by the ``domain`` parameter.

    ldap : ldap3.Connection
        Contains the Connection specified by the ``ldap_connection``
        parameter.
    """
    def __init__(self, domain, ldap_connection):
        self.domain = domain
        self.ldap = ldap_connection

    def __repr__(self):
        message = (
            "domain:    %s\n"
            "server:    %s\n"
            "bound:     %s\n"
        ) % (
            self.domain,
            self.server,
            self.bound
        )
        return message

    def bind(self):
        """Connect to and authenticate with Active Directory."""
        if not self.bound:
            self.ldap.bind()

        if self.bound:
            return True
        else:
            raise ldap3.LDAPBindError('Error connecting to Active Directory')

    def unbind(self):
        """Disconnect from Active Directory"""
        if self.bound:
            self.ldap.unbind()

        if self.bound:
            raise ldap3.LDAPBindError('Error disconnecting from Active Directory')
        else:
            return True

    @property
    def bound(self):
        """State of the connection with Active Directory."""
        return self.ldap.bound

    @property
    def server(self):
        """The specific Active Directory server."""
        return self.ldap.server.host

    @property
    def domain_dn(self):
        """The ldap search base string for the domain"""
        return "dc={}".format(",dc=".join(self.domain.split(".")))

# </ADConnection>

# <new_ad_connection>
def new_ad_connection(domain,
                      username,
                      password,
                      server_list=None,
                      use_ssl=True):
    """
    Creates and returns a ADConnection object to one of the domain
    controllers specified by the domain parameter. Supports the use of
    SSL / LDAPs for additional functions.

    Parameters
    ----------

    domain : str
        Specifies the Active Directory ``domain`` to connect to. By
        default one of domain controllers are selected at random to
        connect to.

    username : str
        Specifies the ``username`` of an account with permissions to
        the Active Directory ``domain``.

    password : str
        Specifies the ``password`` of the account specified by
        ``username`` with permissions to the Active Directory
        ``domain``.

    server_list : list
        [Optional] Specifies the list of domain controllers to
        connection to. By default one of the domain controllers are
        selected at random.

    use_ssl : bool
        [Optional] Specifies if we should connect to Active Directory
        over SSL using LDAPS (the default is True). If you specify
        false, beyond the normal security considerations, make note
        that some operations will not work over a plain text connection
        such as resetting a password.

        The default behavior of using SSL is to validate the
        certificate. If this behavior is not desired, you may modify
        the connection object returned with the function
        ``set_ad_connection_security`` before binding.

    Returns
    -------

    ADConnection
        An ADConnection object.

    Examples
    --------

    Create a new connection object and get the specified user account::

    >>> from admgmt import new_ad_connection
    >>> from admgmt.user import get_ad_user
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username', 'password')
    >>> user = get_ad_user(conn, 'bob.smith@contoso.com')
    """
    # Validate and get normalized parameters
    domain = utils.safe_str(domain)
    username = utils.safe_str(username)
    password = utils.safe_str(password)
    server_list = utils.safe_server_list(domain, server_list)
    use_ssl = utils.safe_bool(use_ssl)

    # Put together a Tls object
    if use_ssl:
        tls = ldap3.Tls(validate=CERT_REQUIRED)
    else:
        tls = None

    # Build the Server Pool
    server_pool = ldap3.ServerPool(servers=None)
    for server_name in server_list:
        # Get each Server object and add it to the pool
        server_pool.add(
            ldap3.Server(
                host=server_name,
                use_ssl=use_ssl,
                get_info=ldap3.SCHEMA,
                tls=tls
            )
        )

    # Build the Connection object
    connection = ldap3.Connection(
        server=server_pool,
        user=username,
        password=password,
        authentication=ldap3.NTLM,
        return_empty_attributes=True
    )

    # Return the Connection object along with domain information
    if connection:
        return ADConnection(domain, connection)
    else:
        return None

# </new_ad_connection>

# <set_ad_connection_security>
def set_ad_connection_security(connection,
                               validate=CERT_REQUIRED,
                               certificate_file=None,
                               private_key_file=None,
                               private_key_password=None):
    """
    Specify additional security options on a ADConnection object for to
    enable, disable, or configure the use of SSL / LDAPs. Without SSL
    some management functions will be unavailable.

    Parameters
    ----------

    connection : ADConnection
        An ADConnection created with ``new_ad_connection``.

    validate : int
        Specifies if the server certificate must be validated. Possible
        values for this parameter are defined in ``admgmt`` as
        constants and are ``CERT_NONE`` (certificates are ignored),
        ``CERT_OPTIONAL`` (not required, but validated if provided) and
        ``CERT_REQUIRED`` (required and validated). The default is
        CERT_REQUIRED.

    certificate_file : str
        Path to the certificate of the server.

    private_key_file : str
        Path to the file with the private key of the client.

    private_key_password : str
        Specifies the password of the ``private_key_file``.

    Returns
    -------

    bool
        True if successful, False if not

    Examples
    --------

    Create a new connection object and disable the checking of the SSL
    certificate::

    >>> from admgmt import new_ad_connection, set_ad_connection_security
    >>> from admgmt import CERT_NONE
    >>> conn = new_ad_connection('contoso.com', 'contoso\\username','password')
    >>> set_ad_connection_security(conn, CERT_NONE)
    """
    # Validate and get normalized parameters
    connection = utils.safe_connection(connection)
    validate = utils.safe_cert(validate)
    certificate_file = utils.safe_str(certificate_file, None)
    private_key_file = utils.safe_str(private_key_file, None)
    private_key_password = utils.safe_str(private_key_password, None)

    tls = ldap3.Tls(
        local_certificate_file=certificate_file,
        local_private_key_file=private_key_file,
        local_private_key_password=private_key_password,
        validate=validate
    )
    connection.ldap.server.tls = tls

    return bool(connection.ldap.server.tls == tls)

# </set_ad_connection_security>
