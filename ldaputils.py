#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Roberto Morati <robertomorati@gmail.com>'


from ldap import modlist
import ldap
import md5
import base64
import hashlib

# LDAP settings
LDAP_SERVER = 'ldap://xxx.xxx.xxx.xxx'
LDAP_IP_SERVER = ''
LDAP_PASS = ''
AUTH_LDAP_BASE_USER = "CN=,CN=,DC=,DC="
BASE_DN = "CN=,DC=,DC="
LDAP_SIMPLE_BIND = 'CN, password'
LDAP_PORT = 389
PASSWORD_ATTR = "unicodePwd"
AUTH_LDAP_BIND_AS_AUTHENTICATING_USER = True


class LDAP:

    """ 
    Set Defaults and Connect - use the config file
    """

    def __init__(self):
        """ Set blank username and password, because we aren't managing them yet """
        self.username = None
        self.password = None
        self.base_username = AUTH_LDAP_BASE_USER
        self.ldap_server = LDAP_SERVER
        self.ldap_bind = LDAP_SERVER
        self.username = AUTH_LDAP_BASE_USER
        self.password = LDAP_PASS
        self.ldap_simple_bind = LDAP_SIMPLE_BIND
        self.protocol_version = ldap.VERSION3
        self.ldap_port = LDAP_PORT
        self.ldap_ip = LDAP_IP_SERVER

    """ 
    For user connections. 
    """

    def connection(self):
        try:
            # DeprecationWarning: ldap.open() is deprecated!
            # Use ldap.initialize() instead.
            #l = ldap.open(self.ldap_server)
            l = ldap.initialize(self.ldap_server)
            l.protocol_version = self.protocol_version
            l.simple_bind_s(self.username, self.password)
            #l.simple_bind_s(self.ldap_bind, self.password)
            return l
        except ldap.INVALID_CREDENTIALS, e:
            return None

    """
    Verify if password it's ok
    """

    def check_password_ldap(self, username, password):
        try:
            try:
                userdn = "CN=" + username + "," + BASE_DN
                l = ldap.initialize(LDAP_SERVER)
                l.protocol_version = self.protocol_version
                l.simple_bind_s(userdn, password)
                l.unbind_s()
                return True
            except ldap.INVALID_CREDENTIALS, e:
                return False
        except ldap.LDAPError, e:  # error
            return None

    """
    For create user    
    """

    def create_user(self, givenName, last_name, email, telefone, username, password):
        try:
            l = LDAP()
            l = l.connection()
            dn = "CN=" + username + "," + BASE_DN
            attrs = {}
            attrs['cn'] = username
            attrs['givenName'] = givenName
            attrs['sn'] = last_name
            attrs['objectclass'] = ['top', 'person', 'organizationalPerson', 'user']
            attrs['mail'] = email
            attrs['userPassword'] = '{SSHA}' + base64.b64encode(hashlib.sha1(password).digest())
            attrs['telephoneNumber'] = telefone
            attrs["sAMAccountName"] = username
            attrs["UserAccountControl"] = '66048'
            attrs['userPrincipalName'] = username

            # Convert our dict to nice syntax for the add-function using modlist-module
            ldif = modlist.addModlist(attrs)

            try:

                # Do the actual synchronous add-operation to the ldapserver
                l.add_s(dn, ldif)

                # Set AD password
                unicode_pass = unicode("\"" + str(password) + "\"", "iso-8859-1")
                password_value = unicode_pass.encode("utf-16-le")
                add_pass = [(ldap.MOD_REPLACE, PASSWORD_ATTR, [password_value])]
                l.modify_s(dn, add_pass)

            except ldap.LDAPError, e:
                # remove, and in the next request...create user
                l.delete(dn)
                # print "Create user ldap error: %s" % (e.args)
                return False

            # Its nice to the server to disconnect and free resources when done
            l.unbind_s()
            return True
        except ldap.LDAPError, error:
            return False

    """
    For change user    
    """

    def change_user(self, result_search, givenName, last_name, email, telefone, username, password):
        try:
            l = LDAP()
            l = l.connection()
            dn = "CN=" + username + "," + BASE_DN
            attrs = {}
            attrs['cn'] = username
            attrs['givenName'] = givenName
            attrs['sn'] = last_name
            attrs['objectclass'] = ['top', 'person', 'organizationalPerson', 'user']
            attrs['mail'] = email
            attrs['telephoneNumber'] = telefone
            attrs['userPassword'] = '{SSHA}' + base64.b64encode(hashlib.sha1(password).digest())
            attrs["sAMAccountName"] = username
            attrs["UserAccountControl"] = '66048'
            attrs['userPrincipalName'] = username

            # String to dict
            result_search = eval(result_search)

            # Convert our dict to nice syntax for the add-function using modlist-module
            ldif = modlist.modifyModlist(result_search, attrs)

            # if changed data
            if ldif != []:
                # Do the actual modification
                try:

                    # modify AD password
                    unicode_pass = unicode("\"" + str(password) + "\"", "iso-8859-1")
                    password_value = unicode_pass.encode("utf-16-le")

                    # enconde new password
                    newpass = '{SSHA}' + base64.b64encode(hashlib.sha1(password).digest())
                    l.passwd(dn, password, newpass)
                    add_pass = [(ldap.MOD_REPLACE, PASSWORD_ATTR, [password_value])]
                    # first do it to validate password
                    l.modify_s(dn, add_pass)  # throws exception if password invalid

                    # second update the user in the ldap
                    # Do the actual synchronous add-operation to the ldapserver
                    # modify userPassword and another informations
                    l.modify_s(dn, ldif)

                except ldap.LDAPError, e:
                    # l.delete(dn)
                    # print "Update user ldap error: %s" % (e.args)
                    return False

            # Its nice to the server to disconnect and free resources when done
            l.unbind_s()
            return True
        except ldap.LDAPError, error:
            return False

    """
    For search user
    """

    def search_user(self, username):
        l = LDAP()
        l = l.connection()
        # The next lines will also need to be changed to support your search requirements and directory
        baseDN = BASE_DN
        searchScope = ldap.SCOPE_SUBTREE
        # retrieve all attributes - again adjust to your needs - see documentation for more options
        retrieveAttributes = None
        searchFilter = "cn=" + username

        buffer_old_data = []
        try:
            ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
            result_set = []
            while 1:
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                    # return False
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
                        buffer_old_data = "{"
                    for i in range(len(result_set)):
                        for entry in result_set[i]:
                            try:
                                buffer_old_data += "'cn':" + "'" + str(entry[1]['cn'][0]) + "'"
                                buffer_old_data += ",'givenName':" + "'" + str(entry[1]['givenName'][0]) + "'"
                                buffer_old_data += ",'sn':" + "'" + str(entry[1]['sn'][0]) + "'"
                                buffer_old_data += ",'mail':" + "'" + str(entry[1]['mail'][0]) + "'"
                                buffer_old_data += ",'telephoneNumber':" + "'" + str(entry[1]['telephoneNumber'][0]) + "'"
                                buffer_old_data += ",'userPassword':" + "'" + str(entry[1]['userPassword'][0]) + "'"
                                buffer_old_data += ",'sAMAccountName':" + "'" + str(entry[1]['sAMAccountName'][0]) + "'"
                                buffer_old_data += ",'UserAccountControl':" + "'" + str("66048") + "'"
                                buffer_old_data += ",'userPrincipalName':" + "'" + str(entry[1]['userPrincipalName'][0]) + "'"
                                buffer_old_data += ",'objectclass':" + "['top', 'person', 'organizationalPerson', 'user']"
                                buffer_old_data += "} "
                            except:
                                pass
                    # here you don't have to append to a list
                    # you could do whatever you want with the individual entry
                    # The appending to list is just for illustration.
            return buffer_old_data
        except ldap.LDAPError, e:
            return False


def encodingMD5(newpassword):
    """
    MD5 encoding
    """
    m = md5.new()
    m.update(newpassword)
    encpassword = '{MD5}%s' % (base64.encodestring(m.digest()))

    return encpassword.strip()
