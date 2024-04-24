/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class LDAPServerTest {

    /**
     * Attempt to parse a user DN string.
     */
    @Test
    public void testUserDnParsing() {
        LDAPServer server = new LDAPServer("ldap://localhost:10386");

        String commonName = "Albert Einstein";
        String accountName = "alby";
        String[] ou = {"User Accounts"};
        String[] dc = {"sas", "com"};

        StringBuffer query = new StringBuffer();
        query.append(server.getCommonNameField() + "=" + commonName);
        query.append(",");
        query.append(server.getOrganizationalUnitField() + "=" + ou[0]);
        query.append(",");
        query.append(server.getDomainComponentField() + "=" + dc[0]);
        query.append(",");
        query.append(server.getDomainComponentField() + "=" + dc[1]);

        // Parse the string we just constructed
        LDAPUser user = new LDAPUser();
        user.setAccountName(accountName);
        try {
            server.setObjectValuesFromString(user, query.toString());
        } catch (LDAPException ex) {
            fail("Failed to construct LDAP user from query string: " + ex.getMessage());
        }

        // Validate that the fields were set correctly
        assertTrue(commonName.equals(user.getCommonName()));
        assertTrue(accountName.equals(user.getAccountName()));

        // Test OU fields
        int idxOU = 0;
        for (String actual : user.getOrganizationalUnits()) {
            String expected = ou[idxOU];
            assertTrue(expected.equals(actual));
            idxOU++;
        }

        // Test DC fields
        int idxDC = 0;
        for (String actual : user.getDomainComponents()) {
            String expected = dc[idxDC];
            assertTrue(expected.equals(actual));
            idxDC++;
        }
    }

}
