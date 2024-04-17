/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to establish a connection to an external LDAP server on the network.
 * An admin account is used to connect to the LDAP server and query the server for information
 * about the user who is authenticating.  This is necessary in order to map a username to the
 * user's distinguished name (DN).  This "admin" account is referred to as a "bind" account
 * and only needs permission to query the LDAP server for user or group information.
 */
public class LDAPServer {
    private static final Logger logger = LoggerFactory.getLogger(LDAPServer.class);

    /** List of LDAP fields to return from a user query */
    // See https://docs.microsoft.com/en-us/windows/win32/ad/address-book-properties
    private static String[] userAttributes = {
        LDAPObject.ACCOUNTNAME_FIELD,
        LDAPObject.COMMONNAME_FIELD,
        LDAPObject.EMAIL_FIELD,
        LDAPUser.MEMBEROF_FIELD
    };

    /** Server protocol, host, and port information for connecting to the LDAP server */
    private String uri = null;

    /** Context used to query the LDAP server */
    private DirContext bindContext = null;

    /**
     * Construct a class for querying LDAP and authenticating users.
     * The user and password information should correspond to an LDAP service account
     * that can be used to access the server and query for user or group information.
     *
     * @param uri   LDAP connection information
     * @param user  LDAP user information required for connecting to the LDAP server
     * @param pass  LDAP password required for connecting to the LDAP server
     * @throws LDAPException if the LDAP connection fails
     */
    public LDAPServer(String uri, LDAPUser user, String pass) throws LDAPException {
        this.uri = uri;

        // Establish a connection to the LDAP server using the bind credentials
        bindContext = getLdapContext(user, pass);
    }

    /**
     * Return the server URI
     *
     * @return  Server URI
     */
    public String getURI() {
        return uri;
    }

    /**
     * Return an LDAP context that can be used to establish a connection to the LDAP server.
     *
     * @param user    User LDAP information that can be used to construct the full DN string
     * @param pass    Password for the user
     * @return A context for connecting to the LDAP server using these credentials
     * @throws LDAPException if the credentials are invalid or a connection cannot be established
     */
    private DirContext getLdapContext(LDAPUser user, String pass) throws LDAPException {
        // Construct a fully qualified LDAP distinquished name that can be used to authenticate the user
        // The LDAPUser.toString() method might have other junk in the result that causes authentication to fail
        String delimiter = ",";
        StringBuffer userDn = new StringBuffer();
        if (user.hasCommonName()) {
            if (userDn.length() > 0) {
                userDn.append(delimiter);
            }
            userDn.append("CN=" + user.getCommonName());
        }

        if (user.hasOrganizationalUnits()) {
            for (String org : user.getOrganizationalUnits()) {
                if (userDn.length() > 0) {
                    userDn.append(delimiter);
                }
                userDn.append("OU=" + org);
            }
        }

        if (user.hasDomainComponents()) {
            for (String component : user.getDomainComponents()) {
                if (userDn.length() > 0) {
                    userDn.append(delimiter);
                }
                userDn.append("DC=" + component);
            }
        }

        logger.info("SSDEBUG: Attempting to authenticate user: " + userDn.toString());
        Hashtable<String,String> env = new Hashtable <String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn.toString());
        env.put(Context.SECURITY_CREDENTIALS, pass);
        env.put(Context.PROVIDER_URL, uri);

        DirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException nex) {
            throw new LDAPException("Failed to establish a context to query the LDAP server.", nex);
        }

        return ctx;
    }

    /**
     * Connect to the LDAP server and get information about the specified user.
     * A null will be returned if the user does not exist.
     *
     * @param field      LDAP field name (cn, sAMAccountName, mail)
     * @param value      LDAP field value to search for
     * @return User information
     * @throws LDAPException if an error occurs when connecting to the LDAP server
     */
    public LDAPUser getUser(String field, String value) throws LDAPException {
        // Examples:
        //   1. https://gist.github.com/jbarber/2909828
        //   2. http://www.javaxt.com/wiki/Tutorials/Windows/How_to_Authenticate_Users_with_Active_Directory
        //   3. http://roufid.com/java-ldap-ssl-authentication/

        // Query for the user DN so that it can be used to validate the password
        LDAPUser targetUser = null;
        String filter = "(" + field + "=" + value + ")";
        SearchControls search = new SearchControls();
        search.setSearchScope(SearchControls.SUBTREE_SCOPE);
        search.setReturningAttributes(userAttributes);
        try {
            NamingEnumeration<SearchResult> answer = bindContext.search("", filter, search);
            if (answer.hasMore()) {
                // Pick the first result in the search results (hopefully there is only one)
                SearchResult result = (SearchResult) answer.next();

                // Construct the user object by parsing the full LDAP string
                String userDN = result.getNameInNamespace();
                targetUser = new LDAPUser(userDN);
                targetUser.setValues(result.getAttributes());
            }
            answer.close();
        } catch (NamingException nex) {
            nex.printStackTrace();
        }

        return targetUser;
    }

    /**
     * Connect to the LDAP server and validate that the username and password are valid.
     *
     * @param username   Username to be validated against the LDAP server
     * @param password   Password to be validated against the LDAP server
     * @return TRUE if the password is valid for the specified user
     * @throws LDAPException if an error occurs when connecting to the LDAP server
     */
    public boolean areCredentialsValid(String username, String password)
        throws LDAPException
    {
        boolean validCredentials = false;

        // Query LDAP to get the user information
        LDAPUser user = getUser(LDAPObject.ACCOUNTNAME_FIELD, username);

        // Validate the user password
        DirContext userContext = null;
        if (user != null) {
            try {
                userContext = getLdapContext(user, password);
                validCredentials = true;
            } catch (LDAPException ex) {
                // Authentication will throw an exception if the password is not valid
                logger.debug("Failed to authenticate user: " + user.toString() + " (" + ex.toString() + ")");
                validCredentials = false;
            }
        }

        return validCredentials;
    }

}
