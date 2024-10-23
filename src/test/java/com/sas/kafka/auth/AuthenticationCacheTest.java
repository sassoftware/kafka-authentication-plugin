/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.security.SecureRandom;
import java.util.Date;

public class AuthenticationCacheTest {

    /** Create a salt for the test credential */
    private byte[] passwordSalt = new byte[16];

    /** Username for the test credential */
    private static final String testUsername = "testuser";

    /** Password for the test credential */
    private static final String testPassword = "testpass1234";

    /** Set the max number of auth attempts to cache for each username/password attempted */
    private static final int MAX_CACHE_DEPTH = 10;

    /**
     * Construct the test class and initialize any test variables.
     */
    public AuthenticationCacheTest() {
        // Generate a random password salt
        SecureRandom random = new SecureRandom();
        random.nextBytes(passwordSalt);
    }

    /**
     * Initialize a dummy cache and test that the attempt history can be
     * accessed and a valid attempt can be retrieved.
     */
    @Test
    public void testCacheRetrieval() {
        // Define a start date to use as fixed point in time for referencing in the test
        Date startDate = new Date();


        // Define a prefix that will be used in the status message of each attempt
        String attemptMessagePrefix = "Failed attempt ";

        // Create a cache to test the authentication attempt retrieval
        AuthenticationCache authCache = new AuthenticationCache();

        // Create a credential to put in the cache
        AuthenticationCredential credential = new AuthenticationCredential(testUsername, testPassword, passwordSalt);

        // Generate multiple authentication attempts and add them to the cache
        int maxCount = 5;
        for (int count = 1; count <= maxCount; count++) {
            AuthenticationAttempt attempt = new AuthenticationAttempt(credential);

            // Add a status and message to make it easy to identify the attempt
            attempt.setStatus(AuthenticationStatus.FAILURE);
            attempt.setStatusMessage(attemptMessagePrefix + count);

            // Increment the timestamp of each attempt by 1 second for each attempt
            int timeOffset = count * 1000;
            Date startTimestamp = new Date(startDate.getTime() + timeOffset);
            attempt.setStartDate(startTimestamp);

            // Set an end date for each attempt that is 30 ms after the start date
            Date endTimestamp = new Date(startTimestamp.getTime() + 30);
            attempt.setEndDate(endTimestamp);

            // Add the attempt to the cache
            try {
                authCache.add(attempt);
            } catch (AuthenticationCredentialsException ex) {
                fail("Failed to create an authentication attempt: " + ex.getMessage());
            }
        }

        // Assert that the number of attempts in the history is accurate
        AuthenticationHistory history = authCache.getAttemptHistory(credential);
        assertNotNull(history);
        assertTrue(history.getAttemptCount() == maxCount);

        // Assert that the most recent attempt has the latest timestamp
        AuthenticationAttempt lastAttempt = authCache.getMostRecentAttempt(credential);
        assertNotNull(lastAttempt);
        assertTrue(lastAttempt.getStatusMessage().equals(attemptMessagePrefix + maxCount));

    }

    /**
     * Test that the cache is adding elements correctly.
     */
    @Test
    public void testCacheGrowth() {
        // Initialize an empty cache
        AuthenticationCache authCache = new AuthenticationCache();

        // Create a credential to put in the cache
        AuthenticationCredential credential = new AuthenticationCredential(testUsername, testPassword, passwordSalt);

        // Continually add new authentication attempts to the cache until the max depth is reached
        authCache.setMaxDepth(MAX_CACHE_DEPTH);
        for (int count = 1; count <= MAX_CACHE_DEPTH; count++) {
            AuthenticationAttempt attempt = new AuthenticationAttempt(credential);
            try {
                authCache.add(attempt);
            } catch (AuthenticationCredentialsException ex) {
                fail("Failed to add new attempt to the credential cache: " + ex.getMessage());
            }

            // Test that the number of cached attempts matches the number created by this loop
            assertTrue(authCache.getAttemptHistoryCount(credential) == count);
        }

        // Add an attempt beyond the max to ensure that the pruning works correctly
        AuthenticationAttempt extraAttempt = new AuthenticationAttempt(credential);
        try {
            authCache.add(extraAttempt);
        } catch (AuthenticationCredentialsException ex) {
            fail("Failed to add extra attempt to the credential cache: " + ex.getMessage());
        }
        assertTrue(authCache.getAttemptHistoryCount(credential) == MAX_CACHE_DEPTH);
    }

    /**
     * Test the authentication exception.
     */
    @Test
    public void testExceptions() {
        String credExMessage = "Doh!  This is an exception.";
        AuthenticationCredentialsException credEx = new AuthenticationCredentialsException(credExMessage);
        credExMessage.equals(credEx.getMessage());
    }
}
