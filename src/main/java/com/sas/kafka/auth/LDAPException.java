/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;


/**
 * This class represents an exception that occurs when interacting with
 * the LDAP server or data objects.
 */
public class LDAPException extends Exception {

    /**
     * Construct an exception containing details about the LDAP failure.
     *
     * @param  message   Text which describes the cause of the failure
     */
    public LDAPException(String message) {
        super(message);
    }

    /**
     * Construct an exception containing details about the LDAP failure.
     *
     * @param  message   Text which describes the cause of the failure
     * @param  cause    Exception which caused the failure
     */
    public LDAPException(String message, Throwable cause) {
        super(message, cause);
    }

}
