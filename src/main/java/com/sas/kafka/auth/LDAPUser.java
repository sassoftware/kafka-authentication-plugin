/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

/**
 * Information about an LDAP user.
 */
public class LDAPUser extends LDAPObject {

    /** LDAP field containing the groups that the user belongs to */
    public static final String MEMBEROF_FIELD = "memberOf";

    /** List of groups that the user belongs to */
    private List<LDAPGroup> groups = new ArrayList<LDAPGroup>();

    /**
     * Construct an empty object.
     */
    public LDAPUser() {
    }

    /**
     * Construct a object by parsing the LDAP query string.  This is the reverse
     * of the toString() operation.
     *
     * @param  query   LDAP query string
     * @throws LDAPException if the query string is null or empty
     */
    public LDAPUser(String query) throws LDAPException {
        if ((query != null) && (query.length() > 0)) {
            fromString(this, query);
        } else {
            throw new LDAPException("The LDAP user query parameter must not be a null or empty string.");
        }
    }

    /**
     * Determine if the user belongs to any groups.
     *
     * @return TRUE if the user belongs to any groups
     */
    public boolean hasGroups() {
        return ((groups != null) && (groups.size() > 0));
    }

    /**
     * Set the list of LDAP groups that the user belongs to.
     *
     * @param  list   Groups
     */
    public void setGroups(Collection<LDAPGroup> list) {
        groups = new ArrayList<LDAPGroup>(list);
    }

    /**
     * Return the list of LDAP groups that the user belongs to.
     *
     * @return List of groups
     */
    public Collection<LDAPGroup> getGroups() {
        return groups;
    }

    /**
     * Add a group to the list.
     *
     * @param  group  LDAP group
     */
    public void addGroup(LDAPGroup group) {
        // Make sure the list has been initialized
        if (groups == null) {
            groups = new ArrayList<LDAPGroup>();
        }

        // Add the group to the list if it does not already exist
        if (!groups.contains(group)) {
            groups.add(group);
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
        super.setValues(attrs);

        Attribute memberOf = attrs.get(MEMBEROF_FIELD);
        if ((memberOf != null) && (memberOf.getAll() != null)) {
            // Iterate over each group and create an LDAP object from the DN string
            NamingEnumeration groupList = memberOf.getAll();
            while (groupList.hasMore()) {
                LDAPGroup group = new LDAPGroup(groupList.next().toString());
                addGroup(group);
            }
        }
    }

}
