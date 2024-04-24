/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.util.Arrays;

public class LDAPGroupTest {

    /**
     * Test that a group correctly contains a list of users.
     */
    @Test
    public void testGroupWithUsers() {
        String[] dc = {"sas", "com"};

        // Construct a group
        LDAPGroup group = new LDAPGroup();
        group.setCommonName("Cattle");
        group.setDomainComponents(Arrays.asList(dc));

        // Construct users for the group
        LDAPUser brownCow = new LDAPUser();
        brownCow.setAccountName("bcow");
        brownCow.setCommonName("Brown Cow");
        brownCow.setDomainComponents(Arrays.asList(dc));
        group.addUser(brownCow);

        LDAPUser whiteCow = new LDAPUser();
        whiteCow.setAccountName("wcow");
        whiteCow.setCommonName("White Cow");
        whiteCow.setDomainComponents(Arrays.asList(dc));
        group.addUser(whiteCow);

        // Validate that the fields were set correctly
        assertNotNull(group.getUsers());
        assertTrue(group.getUsers().size() == 2);
    }

}
