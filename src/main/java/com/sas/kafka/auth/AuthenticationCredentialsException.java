/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

/**
 * This class represents an exception that occurs when interacting with
 * authentication credentials.
 */
public class AuthenticationCredentialsException extends Exception {

    /**
     * Construct an exception containing details about the credentials issue.
     *
     * @param  message   Text which describes the cause of the issue
     */
    public AuthenticationCredentialsException(String message) {
        super(message);
    }

    /**
     * Construct an exception containing details about the LDAP failure.
     *
     * @param  message   Text which describes the cause of the failure
     * @param  cause    Exception which caused the failure
     */
    public AuthenticationCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
