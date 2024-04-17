/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.StringTokenizer;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Information about an LDAP object.
 */
public class LDAPObject extends Object {

    /** Delimiter used in the LDAP query string produced by the toString method */
    public static final String FIELD_DELIMITER = ",";

    /** LDAP field for the organizational unit (OU) */
    public static final String ORGANIZATIONAL_UNIT_FIELD = "ou";

    /** LDAP field for the domain component (DU) */
    public static final String DOMAIN_COMPONENT_FIELD = "dc";

    /** LDAP field used for the distinguished name */
    public static final String DISTINGUISHEDNAME_FIELD = "distinguishedName";

    /** LDAP field used for the common name */
    public static final String COMMONNAME_FIELD = "cn";

    /** LDAP field used for the name */
    public static final String NAME_FIELD = "name";

    /** LDAP field used for the email address */
    public static final String EMAIL_FIELD = "mail";

    /** LDAP field used for the username */
    public static final String ACCOUNTNAME_FIELD = "sAMAccountName";


    /** The LDAP account name */
    private String accountName = null;

    /** The LDAP common name (CN) */
    private String commonName = null;

    /** The user email address */
    private String email = null;

    /** The LDAP organizational units */
    private List<String> organizationalUnits = null;

    /** The LDAP domain components */
    private List<String> domainComponents = new ArrayList<String>();


    /**
     * Construct an empty object.
     */
    public LDAPObject() {
    }

    /**
     * Construct a object by parsing the LDAP query string.  This is the reverse
     * of the toString() operation.
     *
     * @param  query   LDAP query string
     * @throws LDAPException if the query string is null or empty
     */
    public LDAPObject(String query) throws LDAPException {
        fromString(this, query);
    }

    /**
     * Set the LDAP account name (username).
     *
     * @param  name  Account name
     */
    public void setAccountName(String name) {
        this.accountName = name;
    }

    /**
     * Return the LDAP account name (username).
     *
     * @return  Account name
     */
    public String getAccountName() {
        return accountName;
    }

    /**
     * Return true if the account name is set.
     *
     * @return TRUE if the account name is set
     */
    public boolean hasAccountName() {
        return ((accountName != null) && (accountName.trim().length() > 0));
    }

    /**
     * Set the LDAP common name for the object.
     *
     * @param  name  Common name
     */
    public void setCommonName(String name) {
        this.commonName = name;
    }

    /**
     * Return the LDAP common name for the object.
     *
     * @return  Common name
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Return true if the common name is set.
     *
     * @return TRUE if the common name is set
     */
    public boolean hasCommonName() {
        return ((commonName != null) && (commonName.trim().length() > 0));
    }

    /**
     * Set the email address.
     *
     * @param  address    Email address
     */
    public void setEmail(String address) {
        this.email = address;
    }

    /**
     * Return the email address.
     *
     * @return  Email address
     */
    public String getEmail() {
        return email;
    }

    /**
     * Return true if an email address is set.
     *
     * @return  TRUE if an email address is set.
     */
    public boolean hasEmail() {
        return ((email != null) && (email.trim().length() > 0));
    }

    /**
     * Set the list of LDAP organizational unit names for the object.
     *
     * @param  list  organizational unit name
     */
    public void setOrganizationalUnits(Collection<String> list) {
        organizationalUnits = new ArrayList<String>(list);
    }

    /**
     * Return the list of LDAP organizational unit names for the object.
     *
     * @return  list of organizational unit names
     */
    public Collection<String> getOrganizationalUnits() {
        return organizationalUnits;
    }

    /**
     * Return true if there are any organizational units.
     *
     * @return  TRUE if organizational units exist
     */
    public boolean hasOrganizationalUnits() {
        return ((organizationalUnits != null) && (organizationalUnits.size() > 0));
    }

    /**
     * Add an organizational unit to the list.
     *
     * @param  org  Organizational unit name
     */
    public void addOrganizationalUnit(String org) {
        // Make sure the list has been initialized
        if (organizationalUnits == null) {
            organizationalUnits = new ArrayList<String>();
        }

        // Add the org unit to the list if it does not already exist
        if (!organizationalUnits.contains(org)) {
            organizationalUnits.add(org);
        }
    }

    /**
     * Set the list of domain components for the object.
     *
     * @param  list   Domain components
     */
    public void setDomainComponents(Collection<String> list) {
        domainComponents = new ArrayList<String>(list);
    }

    /**
     * Return the list of domain components for the object, or null if none are defined.
     *
     * @return List of domain components
     */
    public Collection<String> getDomainComponents() {
        return domainComponents;
    }

    /**
     * Return true if there are any organizational units.
     *
     * @return  TRUE if organizational units exist
     */
    public boolean hasDomainComponents() {
        return ((domainComponents != null) && (domainComponents.size() > 0));
    }

    /**
     * Add a domain component to the list.
     *
     * @param  component  Domain component
     */
    public void addDomainComponent(String component) {
        // Make sure the list has been initialized
        if (domainComponents == null) {
            domainComponents = new ArrayList<String>();
        }

        // Add the component to the list if it does not already exist
        if (!domainComponents.contains(component)) {
            domainComponents.add(component);
        }
    }

    /**
     * Return the object as an LDAP string.
     *
     * @return String representation of the object
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();

        if (hasAccountName()) {
            if (sb.length() > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(ACCOUNTNAME_FIELD + "=" + accountName);
        }

        if (hasCommonName()) {
            if (sb.length() > 0) {
                sb.append(FIELD_DELIMITER);
            }
            sb.append(COMMONNAME_FIELD + "=" + commonName);
        }

        if (hasOrganizationalUnits()) {
            for (String org : organizationalUnits) {
                if (sb.length() > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append("OU=" + org);
            }
        }

        if (hasDomainComponents()) {
            for (String component : domainComponents) {
                if (sb.length() > 0) {
                    sb.append(FIELD_DELIMITER);
                }
                sb.append("DC=" + component);
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
    public static void fromString(LDAPObject obj, String query) throws LDAPException {
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

                if (name.equalsIgnoreCase("CN")) {
                    obj.setCommonName(value);
                } else if (name.equalsIgnoreCase("OU")) {
                    obj.addOrganizationalUnit(value);
                } else if (name.equalsIgnoreCase("DC")) {
                    obj.addDomainComponent(value);
                }
            }
        }
    }

    /**
     * Determine if the LDAP object is equal to another object.
     * Equality is determined by converting each object to a string and then
     * comparing the equality.
     *
     * @param  obj   The object to compare to for equality
     * @return TRUE if the objects are the same.
     */
    public boolean equals(Object obj) {
        if (obj instanceof LDAPObject) {
            return toString().equalsIgnoreCase(obj.toString());
        } else {
            return false;
        }
    }

    /**
     * Populate the LDAP object with data from the query results.
     *
     * @param attrs   LDAP query result attributes
     * @throws NamingException if the attributes contain invalid data
     * @throws LDAPException if an error occurs setting the LDAP values from the attribute data
     */
    protected void setValues(Attributes attrs) throws LDAPException, NamingException {
        Attribute attrAccountName = attrs.get(ACCOUNTNAME_FIELD);
        if ((attrAccountName != null) && (attrAccountName.get() != null)) {
            setAccountName(attrAccountName.get().toString());
        }

        Attribute attrCommonName = attrs.get(COMMONNAME_FIELD);
        if ((attrCommonName != null) && (attrCommonName.get() != null)) {
            setCommonName(attrCommonName.get().toString());
        }

        Attribute attrEmail = attrs.get(EMAIL_FIELD);
        if ((attrEmail != null) && (attrEmail.get() != null)) {
            setEmail(attrEmail.get().toString());
        }

    }


}
