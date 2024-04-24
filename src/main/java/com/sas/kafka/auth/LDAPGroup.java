/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


/**
 * Information about an LDAP group.
 */
public class LDAPGroup extends LDAPObject {

    /** List of users that belong to the group */
    private List<LDAPUser> users = new ArrayList<LDAPUser>();

    /**
     * Construct an empty object.
     */
    public LDAPGroup() {
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

}
