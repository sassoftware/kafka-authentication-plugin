/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
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

    /** Delimiter used in the LDAP query string produced by the toString method */
    public static final String FIELD_DELIMITER = ",";

    /** LDAP field used for the organizational unit */
    public String organizationalUnitField = "ou";

    /** LDAP field used for the domain component */
    public String domainComponentField = "dc";

    /** LDAP field used for the common name */
    public String commonNameField = "cn";

    /** LDAP field used for the email address */
    public String emailField = "mail";

    /** LDAP field used for the username */
    public String accountNameField = "sAMAccountName";

    /** LDAP field used to indicate a group relationship */
    public String memberOfField = "memberOf";


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
     */
    public LDAPServer(String uri) {
        this.uri = uri;
    }

    /**
     * Establish a connection to the LDAP server using the LDAP user credentials.
     * Any overrides to the LDAP field names need to be performed before this
     * method is called in order for the DN string to be parsed correctly.
     *
     * @param dn    LDAP user DN information required for connecting to the LDAP server
     * @param pass  LDAP password required for connecting to the LDAP server
     * @throws LDAPException if the LDAP connection fails
     */
    public void connect(String dn, String pass) throws LDAPException {
        // Construct a user object from the DN string
        LDAPUser user = new LDAPUser();
        setObjectValuesFromString(user, dn);

        logger.debug("Parsed bind DN for LDAP connection: " + dn + " -> " + getAuthenticationDn(user));

        // Authenticate with the LDAP server
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
     * Set the LDAP field used to store the domain component (DC).
     *
     * @param  field  Domain component field
     */
    public void setDomainComponentField(String field) {
        this.domainComponentField = field;
    }

    /**
     * Return the LDAP field used to store the domain component (DC).
     *
     * @return  Domain component field
     */
    public String getDomainComponentField() {
        return domainComponentField;
    }

    /**
     * Set the LDAP field used to store the organizational unit (OU).
     *
     * @param  field  Organizational unit field
     */
    public void setOrganizationalUnitField(String field) {
        this.organizationalUnitField = field;
    }

    /**
     * Return the LDAP field used to store the organizational unit (OU).
     *
     * @return  Organizatinal unit field
     */
    public String getOrganizationalUnitField() {
        return organizationalUnitField;
    }

    /**
     * Set the LDAP field used to store the common name (CN).
     *
     * @param  field  Common name field
     */
    public void setCommonNameField(String field) {
        this.commonNameField = field;
    }

    /**
     * Return the LDAP field used to store the common name (CN).
     *
     * @return  Account name field
     */
    public String getCommonNameField() {
        return commonNameField;
    }

    /**
     * Set the LDAP field used to store the account name (username).
     *
     * @param  field  Account name field
     */
    public void setAccountNameField(String field) {
        this.accountNameField = field;
    }

    /**
     * Return the LDAP field used to store the account name (username).
     *
     * @return  Account name field
     */
    public String getAccountNameField() {
        return accountNameField;
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
        String userDn = getAuthenticationDn(user);
        logger.debug("Attempting to authenticate LDAP user: " + userDn);

        Hashtable<String,String> env = new Hashtable <String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn);
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

        /** List of LDAP fields to return from a user query */
        // See https://docs.microsoft.com/en-us/windows/win32/ad/address-book-properties
        String[] userAttributes = {
            accountNameField,
            commonNameField,
            emailField,
            memberOfField
        };

        // Query for the user DN so that it can be used to validate the password
        LDAPUser targetUser = null;
        String filter = "(" + field + "=" + value + ")";
        SearchControls search = new SearchControls();
        search.setSearchScope(SearchControls.SUBTREE_SCOPE);
        search.setReturningAttributes(userAttributes);
        try {
            logger.debug("Attempting to query LDAP for user: " + filter);
            NamingEnumeration<SearchResult> answer = bindContext.search("", filter, search);
            if (answer.hasMore()) {
                // Pick the first result in the search results (hopefully there is only one)
                SearchResult result = (SearchResult) answer.next();
                Attributes attrs = result.getAttributes();

                // Construct the user object by parsing the full LDAP string
                String userDN = result.getNameInNamespace();
                logger.debug("Found user result: " + userDN);
                targetUser = new LDAPUser();
                if ((userDN != null) && (userDN.length() > 0)) {
                    setObjectValuesFromString(targetUser, userDN);
                }

                // Populate the remaining user attributes
                Attribute attrAccountName = attrs.get(accountNameField);
                if ((attrAccountName != null) && (attrAccountName.get() != null)) {
                    targetUser.setAccountName(attrAccountName.get().toString());
                }
        
                Attribute attrCommonName = attrs.get(commonNameField);
                if ((attrCommonName != null) && (attrCommonName.get() != null)) {
                    targetUser.setCommonName(attrCommonName.get().toString());
                }
        
                Attribute attrEmail = attrs.get(emailField);
                if ((attrEmail != null) && (attrEmail.get() != null)) {
                    targetUser.setEmail(attrEmail.get().toString());
                }

                Attribute memberOf = attrs.get(memberOfField);
                if ((memberOf != null) && (memberOf.getAll() != null)) {
                    // Iterate over each group and create an LDAP object from the DN string
                    NamingEnumeration groupList = memberOf.getAll();
                    while (groupList.hasMore()) {
                        LDAPGroup group = new LDAPGroup();
                        setObjectValuesFromString(group, groupList.next().toString());
                        targetUser.addGroup(group);
                    }
                }
        
        
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
        LDAPUser user = getUser(accountNameField, username);

        // Validate the user password
        DirContext userContext = null;
        if (user != null) {
            try {
                userContext = getLdapContext(user, password);
                validCredentials = true;
            } catch (LDAPException ex) {
                // Authentication will throw an exception if the password is not valid
                logger.debug("Failed to authenticate user: " + username + " (" + ex.toString() + ")");
                validCredentials = false;
            }
        } else {
            logger.warn("Failed to locate LDAP user: " + username);
        }

        return validCredentials;
    }

    /**
     * Return the LDAP User as a DN string that can be used during LDAP authentication.
     *
     * @return String representation of the LDAP User
     */
    public String getAuthenticationDn(LDAPUser user) {
        StringBuffer sb = new StringBuffer();

        // Use either the common name or the account name when constructing
        // the DN, but not both.  Prefer the common name if available.
        // Using both will cause an authentication failure.
        if (user.hasCommonName()) {
            if (sb.length() > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(commonNameField + "=" + user.getCommonName());
        } else if (user.hasAccountName()) {
            if (sb.length() > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(accountNameField + "=" + user.getAccountName());
        }

        if (user.hasOrganizationalUnits()) {
            for (String org : user.getOrganizationalUnits()) {
                if (sb.length() > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append(organizationalUnitField + "=" + org);
            }
        }

        if (user.hasDomainComponents()) {
            for (String component : user.getDomainComponents()) {
                if (sb.length() > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append(domainComponentField + "=" + component);
            }
        }

        return sb.toString();
    }

    /**
     * Populate a object by parsing the LDAP query string.  This is the reverse
     * of the toString() operation.
     *
     * @param  obj     LDAP Object to populate from the query string
     * @param  query   LDAP query string
     * @throws LDAPException if the query string is null or empty
     */
    public void setObjectValuesFromString(LDAPObject obj, String query) throws LDAPException {
        if ((query == null) || (query.length() == 0)) {
            throw new LDAPException("The LDAP object query parameter must not be a null or empty string.");
        }

        Pattern pattern = Pattern.compile("(.*?(?<!\\\\)),|.+$");
        Pattern fieldPattern = Pattern.compile("(.*?)=(.*)$");
        Matcher matcher = pattern.matcher(query);
        while (matcher.find()) {
            String field = (matcher.group(1)!=null)?matcher.group(1):matcher.group(0);
            Matcher fieldMatcher = fieldPattern.matcher(field);
            if (fieldMatcher.find()) {
                String name = fieldMatcher.group(1);
                String value = fieldMatcher.group(2).replaceAll("\\\\,",",");

                // Parse the common fields
                if (name.equalsIgnoreCase(commonNameField)) {
                    obj.setCommonName(value);
                } else if (name.equalsIgnoreCase(organizationalUnitField)) {
                    obj.addOrganizationalUnit(value);
                } else if (name.equalsIgnoreCase(domainComponentField)) {
                    obj.addDomainComponent(value);
                }

                // Parse the user specific fields
                if (obj instanceof LDAPUser) {
                    if (name.equalsIgnoreCase(accountNameField)) {
                        ((LDAPUser)obj).setAccountName(value);
                    } else if (name.equalsIgnoreCase(emailField)) {
                        ((LDAPUser)obj).setEmail(value);
                    }
                }

            }
        }
    }

}
