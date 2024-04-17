/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * This class represents a list of authentication attempts.
 */
public class AuthenticationHistory {

    /** Limit the number of attempts that will be recorded */
    private int maxAttempts = 10;

    /** Maintain a list of any authentication attempts */
    private ConcurrentLinkedQueue<AuthenticationAttempt> attempts = new ConcurrentLinkedQueue<AuthenticationAttempt>();

    /**
     * Construct the cache.
     */
    public AuthenticationHistory() {
    }

    /**
     * Set the maximum number of authentication attempts that will be recorded.
     *
     * @param limit Maximum number of attempts to keep track of
     */
    public void setMaxAttempts(int limit) {
        maxAttempts = limit;
        prune();
    }

    /**
     * Return the list of authentication attempts.
     *
     * @return List of attempts
     */
    public AuthenticationAttempt[] getAttempts() {
        return attempts.toArray(new AuthenticationAttempt[0]);
    }

    /**
     * Return the total number of attempts kept in the list.
     *
     * @return Number of attempts saved in the current list
     */
    public int getAttemptCount() {
        if (attempts != null) {
            return attempts.size();
        } else {
            return 0;
        }
    }

    /**
     * Prune the number of authentication attempts kept in the list.
     * This method will automatically be called any time the limit
     * is changed or a new attempt is added.
     */
    public void prune() {
        if ((attempts.size() > 0) && (maxAttempts > 0)) {
            while (attempts.size() > maxAttempts) {
                AuthenticationAttempt prunedAttempt = attempts.remove();
            }
        }
    }

    /**
     * Add an authentication attempt to the list.
     *
     * @param attempt User authentication attempt
     */
    public void add(AuthenticationAttempt attempt) {
        attempts.add(attempt);

        // Invoking prune AFTER the new element is added momentarily causes
        // the size of the history to exceed the limit, but simplifies logic
        // and code maintenance
        prune();
    }

    /**
     * Return the most recent attempt or null if no attempts exist.
     *
     * @return The most recent authentication attempt
     */
    public AuthenticationAttempt getMostRecent() {
        AuthenticationAttempt mostRecent = null;

        Iterator<AuthenticationAttempt> iterator = attempts.iterator();
        while (iterator.hasNext()) {
            AuthenticationAttempt currentAttempt = iterator.next();
            if (mostRecent != null) {
                // Determine if the current attempt is newer than the previusly selected "most recent" attempt
                if (currentAttempt.getStartDate().getTime() > mostRecent.getStartDate().getTime()) {
                    mostRecent = currentAttempt;
                }
            } else {
                // This is the first attempt being evaluated
                mostRecent = currentAttempt;
            }
        }

        return mostRecent;
    }
}


