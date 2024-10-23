/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.security.SecureRandom;

public class AuthenticationCredentialsTest {

    /**
     * Verify that different salts produce different encoded passwords.
     */
    @Test
    public void testCustomSalt() {
        // Create two copies of the same credential, where only the salt is different
        String username = "alberto";
        String password = "supersecret";
        SecureRandom random = new SecureRandom();
        byte[] salt01 = new byte[16];
        random.nextBytes(salt01);
        byte[] salt02 = new byte[16];
        random.nextBytes(salt02);

        // Construct two identical credential objects
        AuthenticationCredential credentialA = new AuthenticationCredential(username, password, salt01);
        AuthenticationCredential credentialB = new AuthenticationCredential(username, password, salt01);
        assertTrue(credentialA.isDuplicate(credentialB));

        // Test that a different salt value produces different encoded passwords
        assertTrue(credentialA.matchesPassword(password, salt01));
        assertFalse(credentialA.matchesPassword(password, salt02));

        // Validate that the password hashing is reproducible
        String encodedPasswordA = credentialA.getEncodedPasswordAsString();
        String encodedPasswordB = credentialB.getEncodedPasswordAsString();
        assertTrue(encodedPasswordA.equals(encodedPasswordB));
    }

    /**
     * Verify that the generated salt for two different objects produces
     * a different password.
     */
    @Test
    public void testDefaultSalt() {
        // Create two copies of the same credential, where only the salt is different
        String username = "alberto";
        String password = "supersecret";

        // Construct two identical credential objects using generated salt values
        AuthenticationCredential credentialA = new AuthenticationCredential(username, password);
        AuthenticationCredential credentialB = new AuthenticationCredential(username, password);

        // The credentials should not be duplicates because the generated salt
        // should produce different encoded passwords.  Otherwise the random number
        // generator is not working or something else is wrong.
        assertFalse(credentialA.isDuplicate(credentialB));

        // Test that password salt encoding is consistent and reproducible
        assertTrue(credentialA.matchesPassword(password, credentialA.getPasswordSalt()));

        // Test that a different salt value produces different encoded passwords
        assertFalse(credentialA.matchesPassword(password, credentialB.getPasswordSalt()));
    }

    /**
     * Verify that the credentials can be converted to and from a string.
     */
    @Test
    public void testStringConversion() {
        String username = "romero";
        String password = "stealthyninja";

        // Create a credential and represent it as a string
        AuthenticationCredential originalCredential = new AuthenticationCredential(username, password);
        String originalSalt = originalCredential.getPasswordSaltAsString();
        String originalString = originalCredential.toString();

        // Parse the string back to a credential
        AuthenticationCredential parsedCredential = AuthenticationCredential.parse(originalString);
        String parsedSalt = parsedCredential.getPasswordSaltAsString();
        String parsedString = parsedCredential.toString();

        // Test that the salt is being parsed correctly
        assertTrue(originalSalt.equals(parsedSalt));

        // Test that the round trip string translation works
        assertTrue(originalString.equals(parsedString));
    }

}
