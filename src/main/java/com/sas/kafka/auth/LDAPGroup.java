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
 * Information about an LDAP group.
 */
public class LDAPGroup extends LDAPObject {

    /** LDAP field containing the users that belong to a group */
    public static final String MEMBER_FIELD = "member";

    /** List of users that belong to the group */
    private List<LDAPUser> users = new ArrayList<LDAPUser>();

    /**
     * Construct an empty object.
     */
    public LDAPGroup() {
    }

    /**
     * Construct a object by parsing the LDAP query string.  This is the reverse
     * of the toString() operation.
     *
     * @param  query   LDAP query string
     * @throws LDAPException if the query string is null or empty
     */
    public LDAPGroup(String query) throws LDAPException {
        fromString(this, query);
    }

    /**
     * Determine if the group contains any users.
     *
     * @return TRUE if the group contains users
     */
    public boolean hasUsers() {
        return ((users != null) && (users.size() > 0));
    }

    /**
     * Set the list of LDAP users that belong to this group
     *
     * @param  list   Users
     */
    public void setUsers(Collection<LDAPUser> list) {
        users = new ArrayList<LDAPUser>(list);
    }

    /**
     * Return the list of LDAP users that belong to the group.
     *
     * @return List of users
     */
    public Collection<LDAPUser> getUsers() {
        return users;
    }

    /**
     * Add a user to the list.
     *
     * @param  user  LDAP user
     */
    public void addUser(LDAPUser user) {
        // Make sure the list has been initialized
        if (users == null) {
            users = new ArrayList<LDAPUser>();
        }

        // Add the user to the list if it does not already exist
        if (!users.contains(user)) {
            users.add(user);
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

        // Find the member field
        // can't use get since it may have other information
        // in the id (ie member;range=1-1499)
        for (NamingEnumeration ae = attrs.getAll(); ae.hasMore();) {
            Attribute attr = (Attribute)ae.next();
            if (attr.getID().startsWith(MEMBER_FIELD) && attr.getAll() != null) {
                // Iterate over each user and create an LDAP object from the DN string
                NamingEnumeration userList = attr.getAll();
                while (userList.hasMore()) {
                    LDAPUser usr = new LDAPUser(userList.next().toString());
                    addUser(usr);
                }
            }
        }
    }
}
