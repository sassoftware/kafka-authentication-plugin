/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class LDAPGroupTest {

    private static final String commonName = "System Admins";
    private static final String accountName = "sysadmins";
    private static final String[] ouNames = {"Groups"};

    /**
     * Construct a test group.
     *
     * @return LDAP group
     * @throws LDAPException if the group creation fails
     */
    private LDAPGroup createGroup() throws LDAPException {
        StringBuffer query = new StringBuffer();
        query.append(LDAPGroup.COMMONNAME_FIELD + "=" + commonName);
        for (String ou : ouNames) {
            query.append(",");
            query.append(LDAPGroup.ORGANIZATIONAL_UNIT_FIELD + "=" + ou);
        }
        query.append(",");
        query.append(LDAPGroup.DOMAIN_COMPONENT_FIELD + "=" + "sas");
        query.append(",");
        query.append(LDAPGroup.DOMAIN_COMPONENT_FIELD + "=" + "com");

        return new LDAPGroup(query.toString());
    }

    /**
     * Construct a user object from an LDAP query string.
     */
    @Test
    public void testGroupConstructor() {
        LDAPGroup group = null;

        // Test that the group constructor works correctly
        try {
            group = createGroup();
        } catch (LDAPException ex) {
            fail("Failed to construct LDAP group from query string: " + ex.getMessage());
        }
        assertNotNull(group);
        assertTrue(commonName.equals(group.getCommonName()));
        assertEquals(ouNames.length, group.getOrganizationalUnits().size());

        // Test that the user list works correctly
        LDAPUser user = new LDAPUser();
        user.setCommonName("Test User");
        group.addUser(user);
        group.getUsers();
        assertEquals(1, group.getUsers().size());
    }

}
