/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

/**
 * The authentication status is used to determine whether the authentication
 * attempt was successful, failed due to bad credentials, or an error due to
 * problems querying the authentication data source.
 */
public enum AuthenticationStatus {
    /** Indicates a successful authentication attempt */
    SUCCESS,
    
    /** Indicates a failed authentication attempt */
    FAILURE,
    
    /** Indicates an error occurred during authentication */
    ERROR
}