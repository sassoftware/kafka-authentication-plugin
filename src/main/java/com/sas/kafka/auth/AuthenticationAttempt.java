/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.Date;

/**
 * This data object represents an attempt by a Kafka client to perform
 * authentication using a username and password.  It can be used to log attempts
 * or cache attempts.
 */
public class AuthenticationAttempt {

    /** Authentication credentials used in the attempt */
    private AuthenticationCredentials credentials = null;

    /** Result of the authentication attempt */
    private AuthenticationStatus status = AuthenticationStatus.FAILURE;

    /** Informational message to provide additional information about the authentication attempt */
    private String statusMessage = null;

    /** Date when the authentication attempt was initiated */
    private Date startDate = new Date();

    /** Date when the authentication attempt was completed */
    private Date endDate = new Date();

    /**
     * Construct an authentication attempt record.
     * The date will be set to the current time by default.
     * The status will be set to FAILURE by default.
     *
     * @param credentials   Username provided by the client
     */
    public AuthenticationAttempt(AuthenticationCredentials credentials) {
        this.credentials = credentials;
    }

    /**
     * Return TRUE if the authentication attempt was successful.
     *
     * @return TRUE if the attempt was successful
     */
    public boolean wasSuccessful() {
        return (status == AuthenticationStatus.SUCCESS);
    }

    /**
     * Return the authentication credentials used in the attempt.
     *
     * @return Authentication credentials
     */
    public AuthenticationCredentials getCredentials() {
        return credentials;
    }

    /**
     * Get the status of the authentication attempt.
     *
     * @return Status returned during the authentication attempt
     */
    public AuthenticationStatus getStatus() {
        return status;
    }

    /**
     * Set the status of the authentication attempt.
     *
     * @param status Status of the authentication attempt
     */
    public void setStatus(AuthenticationStatus status) {
        this.status = status;
    }

    /**
     * Get the status message associated with the authentication attempt.
     *
     * @return Status message associated with the authentication attempt.
     */
    public String getStatusMessage() {
        return statusMessage;
    }

    /**
     * Set the status message associated with the authentication attempt.
     *
     * @param message Status message associated with the authentication attempt.
     */
    public void setStatusMessage(String message) {
        statusMessage = message;
    }

    /**
     * Get the date when the authentication attempt was initiated.
     *
     * @return Starting date of the authentication attempt
     */
    public Date getStartDate() {
        return startDate;
    }

    /**
     * Set the date when the authentication attempt was initiated.
     *
     * @param date  Starting date of the authentication attempt
     */
    public void setStartDate(Date date) {
        startDate = date;
    }

    /**
     * Get the date when the authentication attempt was completed.
     *
     * @return Ending date of the authentication attempt
     */
    public Date getEndDate() {
        return endDate;
    }

    /**
     * Set the date when the authentication attempt was completed.
     *
     * @param date  Ending date of the authentication attempt
     */
    public void setEndDate(Date date) {
        endDate = date;
    }

    /**
     * Return the elapsed time between the start date and the end date
     * in milliseconds.
     *
     * @return Elapsed time in milliseconds
     */
    public long getElapsedTime() {
        if ((startDate != null) && (endDate != null)) {
            return endDate.getTime() - startDate.getTime();
        } else {
            return 0;
        }
    }

    /**
     * Convert the authentication attempt to a string.
     *
     * @return String representing the authentication attempt
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();

        // Include the authentication status
        sb.append(status.toString());

        // Include the username or a dash if no username is available
        if ((credentials != null) && (credentials.getUsername() != null)) {
            sb.append(" " + credentials.getUsername());
        } else {
            sb.append(" -");
        }

        // Include the elapsed time
        sb.append(" [" + getElapsedTime() + " ms]");

        // Include the status message as an optional part at the end of the string
        if ((statusMessage != null) && (statusMessage.length() > 0)) {
            sb.append(" " + statusMessage);
        }

        return sb.toString();
    }

}