/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class LDAPUserTest {

    /**
     * Construct a test user.
     *
     * @return LDAP user
     * @throws LDAPException if the user creation fails
     */
    private LDAPUser createUser() throws LDAPException {
        String commonName = "Albert Einstein";
        String accountName = "alby";

        StringBuffer query = new StringBuffer();
        query.append(LDAPUser.COMMONNAME_FIELD + "=" + commonName);
        query.append(",");
        query.append(LDAPUser.ORGANIZATIONAL_UNIT_FIELD + "=" + "User Accounts");
        query.append(",");
        query.append(LDAPUser.DOMAIN_COMPONENT_FIELD + "=" + "sas");
        query.append(",");
        query.append(LDAPUser.DOMAIN_COMPONENT_FIELD + "=" + "com");

        return new LDAPUser(query.toString());
    }

    /**
     * Construct a user object from an LDAP query string.
     */
    @Test
    public void testUserConstructor() {
        try {
            LDAPUser user = createUser();
        } catch (LDAPException ex) {
            fail("Failed to construct LDAP user from query string: " + ex.getMessage());
        }
    }

}
