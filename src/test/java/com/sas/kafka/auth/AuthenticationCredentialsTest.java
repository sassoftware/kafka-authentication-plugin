/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AuthenticationCredentialsTest {

    /**
     * Initialize a dummy cache and test that the attempt history can be
     * accessed and a valid attempt can be retrieved.
     */
    @Test
    public void testPasswordSalt() {
        // Create two copies of the same credential, where only the salt is different
        String username = "alberto";
        String password = "supersecret";
        SecureRandom random = new SecureRandom();
        byte[] salt01 = new byte[16];
        random.nextBytes(salt01);
        byte[] salt02 = new byte[16];
        random.nextBytes(salt02);

        // Construct two identical credential objects
        AuthenticationCredentials credentialA = new AuthenticationCredentials(username, password, salt01);
        AuthenticationCredentials credentialB = new AuthenticationCredentials(username, password, salt01);
        assertTrue(credentialA.isDuplicate(credentialB));

        // Test that a different salt value produces different encoded passwords
        assertTrue(credentialA.matchesPassword(password, salt01));
        assertFalse(credentialA.matchesPassword(password, salt02));

        // Validate that the password hashing is reproducible
        String encodedPasswordA = credentialA.getEncodedPasswordAsString();
        String encodedPasswordB = credentialB.getEncodedPasswordAsString();
        assertTrue(encodedPasswordA.equals(encodedPasswordB));
    }
}
