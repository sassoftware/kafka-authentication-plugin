/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The authentication logger is used to write authentication attempts to a log file
 * using the same logging framework as the Kafka deployment.  Successful authentication
 * will only be logged when the logging framework is configured to log DEBUG messages.
 */
public class AuthenticationLogger {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationLogger.class);

    /**
     * Log an authentication attempt.
     *
     * @param attempt Authentication Attempt
     */
    public static void log(AuthenticationAttempt attempt) {
        if (attempt.getStatus() == AuthenticationStatus.SUCCESS) {
            // Log a successful attempt only when DEBUG logging is enabled
            logger.debug(attempt.toString());
        } else {
            logger.info(attempt.toString());
        }
    }
}