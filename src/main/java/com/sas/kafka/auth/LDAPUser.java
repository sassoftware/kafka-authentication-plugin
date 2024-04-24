/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Information about an LDAP user.
 */
public class LDAPUser extends LDAPObject {

    /** The LDAP account name */
    private String accountName = null;

    /** The user email address */
    private String email = null;


    /** List of groups that the user belongs to */
    private List<LDAPGroup> groups = new ArrayList<LDAPGroup>();

    /**
     * Construct an empty object.
     */
    public LDAPUser() {
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

}
