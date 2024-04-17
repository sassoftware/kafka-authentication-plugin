/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.security.SecureRandom;
import java.util.Hashtable;

/**
 * This class is used to cache user authentication attempts.
 * This helps to reduce the load on the authentication server and prevent accounts
 * from being locked out due to excessive failed login attempts.
 */
public class AuthenticationCache {

    /**
     * Default maximum number of attempts to keep for each entry in the attempt hashtable.
     */
    private int DEFAULT_MAX_DEPTH = 10;

    /**
     * List of authentication attempts, where the key is a combination of
     * username and base-64 encoded password in the format:
     * <code>username:base64pass</code>
     */
    private Hashtable<String, AuthenticationHistory> attempts = new Hashtable<String, AuthenticationHistory>();

    /**
     * Maximum number of attempts to keep for each entry in the attempt hashtable.
     */
    private int maxDepth = DEFAULT_MAX_DEPTH;

    /**
     * Construct the cache.
     */
    public AuthenticationCache() {
    }

    /**
     * Return the maximum number of attempts to keep for each entry in the cache.
     *
     * @return Max number of attempts to record for each credentials
     */
    public int getMaxDepth() {
        return maxDepth;
    }
    
    /**
     * Set the maximum number of attempts to keep for each entry in the cache.
     *
     * @param limit  Max number of attempts to record for each credential (username/password combination)
     */
    public void setMaxDepth(int limit) {
        maxDepth = limit;
    }

    /**
     * Construct the lookup key for a credential by using the username and password digest
     * to uniquely identify an authentication credential.
     *
     * @param credentials Authentication credentials
     * @return String representing the username and password combination
     * @throws AuthenticationCredentialsException if the username or password digest are null
     */
    private String getCacheKey(AuthenticationCredentials credentials) throws AuthenticationCredentialsException {
        String username = credentials.getUsername();
        if ((username == null) || (username.length() == 0)) {
            throw new AuthenticationCredentialsException("Authentication attempt contains credentials with a null or empty username.");
        }
        String pwDigest = credentials.getEncodedPasswordAsString();
        if (pwDigest == null) {
            throw new AuthenticationCredentialsException("Authentication attempt contains credentials with a null or empty password digest.");
        }

        return username + ":" + pwDigest;
    }
    
    /**
     * Prune the entire cache to remove any entries which fall outside of the cache size
     * or age limits.
     */
    public void prune() {
        if (attempts != null) {
            for (String key : attempts.keySet()) {
                AuthenticationHistory history = attempts.get(key);
                history.prune();
            }
        }
    }

    /**
     * Prune the entire cache to remove any entries for the specified credential which
     * fall outside of the cache size or age limits.
     * 
     * @param credentials  User credential to target when pruning
     */
    public void prune(AuthenticationCredentials credentials) {
        if (attempts != null) {
            try {
                String key = getCacheKey(credentials);
                AuthenticationHistory history = attempts.get(key);
                if (history != null) {
                    history.prune();
                }
            } catch (AuthenticationCredentialsException ex) {
                // If the credentials are invalid, assume no prune is necessary
            }
        }
    }

    /**
     * Add a new attempt to the cache.
     *
     * @param attempt  Authentication attempt
     * @throws AuthenticationCredentialsException if the username or password digest are null
     */
    public void add(AuthenticationAttempt attempt) throws AuthenticationCredentialsException {
        // Handle any error conditions that will prevent the attempt from being recorded in the history
        if (attempt.getCredentials() == null) {
            throw new AuthenticationCredentialsException("Authentication attempt contains null user credentials.");
        }

        // Add the authentication attempt to the cache
        String key = getCacheKey(attempt.getCredentials());
        AuthenticationHistory history = null;
        if (attempts.containsKey(key)) {
            history = attempts.get(key);
            history.add(attempt);
        } else {
            history = new AuthenticationHistory();
            history.add(attempt);
            attempts.put(key, history);
        }

        // Remove excess information from the cache
        prune(attempt.getCredentials());
    }

    /**
     * Return the most recent authentication attempt for the specified user.
     *
     * @param credentials User authentication credentials
     * @return Most recent authentication attempt
     */
    public AuthenticationAttempt getMostRecentAttempt(AuthenticationCredentials credentials) {
        AuthenticationAttempt attempt = null;

        AuthenticationHistory history = getAttemptHistory(credentials);
        if (history != null) {
            attempt = history.getMostRecent();
        }

        return attempt;
    }

    /**
     * Return a list of all authentication attempts cached for the specified user.
     *
     * @param credentials User authentication credentials
     * @return List of authentication attempts
     */
    public AuthenticationHistory getAttemptHistory(AuthenticationCredentials credentials) {
        // Call prune first to ensure this method returns accurate results
        prune(credentials);

        AuthenticationHistory history = null;
        try {
            String key = getCacheKey(credentials);
            history = attempts.get(key);
        } catch (AuthenticationCredentialsException ex) {
            // Assume the credentials are invalid and the history is not found
        }

        return history;
    }

    /**
     * Return the number of authentication attempts cached for the specified user.
     *
     * @param credentials User authentication credentials
     * @return Number of authentication attempts in the cache
     */
    public int getAttemptHistoryCount(AuthenticationCredentials credentials) {
        AuthenticationHistory history = getAttemptHistory(credentials);
        if (history != null) {
            return history.getAttemptCount();
        } else {
            return 0;
        }
    }

    /**
     * Return a string representing the cache history.
     */
    public String toString() {
        StringBuffer buffer = new StringBuffer();

        if (attempts != null) {
            for (String key : attempts.keySet()) {
                buffer.append(key + "\n");
                AuthenticationHistory history = attempts.get(key);
                if (history != null) {
                    for (AuthenticationAttempt attempt : history.getAttempts()) {
                        buffer.append("- " + attempt.toString() + "\n");
                    }
                }
            }
        }

        return buffer.toString();
    }
}

