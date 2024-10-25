/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import com.sun.security.auth.UserPrincipal;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.spi.LoginModule;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Callback handler for the LDAP SASL-based authentication.  This class is registered
 * with the Kafka server by specifying the class name in the <code>server.properties</code>
 * file as:
 * <blockquote><code>
 * listener.name.LISENER_NAME.plain.sasl.server.callback.handler.class=\
 *     com.sas.kafka.auth.KafkaStaticAuthenticationHandler
 * </code></blockquote>
 */
public class KafkaStaticAuthenticationHandler implements AuthenticateCallbackHandler {
    private static final Logger logger = LoggerFactory.getLogger(KafkaStaticAuthenticationHandler.class);

    /** Kafka property specifying a list of static credentials to authenticate against */
    public static final String AUTH_STATIC_CREDENTIALS = "auth.static.credentials";

    /**
     * Define a list of usernames and passwords to authenticate against.
     */
    private Map<String,AuthenticationCredential> staticCredentials = new HashMap<String,AuthenticationCredential>();

    /**
     * Construct the Authentication handler.
     */
    public KafkaStaticAuthenticationHandler() {
    }

    /**
     * Parse a list of statically defined username and passwords into a map.
     * The list of usernames is defined as a whitespace delimited string that
     * looks like this:
     * <code>
     *   user1:password1 user2:password2 user3:password3
     * </code>
     */
    private Map<String,AuthenticationCredential> parseUserList(String list) {
        Map<String,AuthenticationCredential> users = new HashMap<String,AuthenticationCredential>();

        if (list != null) {
            // Split the whitespace delimited list into individual credentials
            String[] unparsedList = list.split("\\s");
            int idx = 0;
            while (idx < unparsedList.length) {
                // Decode the current entry by parsing the credential
                AuthenticationCredential credential = AuthenticationCredential.parse(unparsedList[idx]);
                users.put(credential.getUsername(), credential);
                idx++;
            }
        }

        return users;
    }

    /**
     * Configures this LDAP callback handler by creating a connection to an external
     * LDAP server using the configuration values provided to the method.
     *
     * @param configs Key-value pairs containing the parsed configuration options of
     *        the client or broker. Note that these are the Kafka configuration options
     *        and not the JAAS configuration options. JAAS config options may be obtained
     *        from `jaasConfigEntries` for callbacks which obtain some configs from the
     *        JAAS configuration. For configs that may be specified as both Kafka config
     *        as well as JAAS config (e.g. sasl.kerberos.service.name), the configuration
     *        is treated as invalid if conflicting values are provided.
     * @param saslMechanism Negotiated SASL mechanism. For clients, this is the SASL
     *        mechanism configured for the client. For brokers, this is the mechanism
     *        negotiated with the client and is one of the mechanisms enabled on the broker.
     * @param jaasConfigEntries JAAS configuration entries from the JAAS login context.
     *        This list contains a single entry for clients and may contain more than
     *        one entry for brokers if multiple mechanisms are enabled on a listener using
     *        static JAAS configuration where there is no mapping between mechanisms and
     *        login module entries. In this case, callback handlers can use the login module in
     *        `jaasConfigEntries` to identify the entry corresponding to `saslMechanism`.
     *        Alternatively, dynamic JAAS configuration option
     *        {@link org.apache.kafka.common.config.SaslConfigs#SASL_JAAS_CONFIG} may be
     *        configured on brokers with listener and mechanism prefix, in which case
     *        only the configuration entry corresponding to `saslMechanism` will be provided
     *        in `jaasConfigEntries`.
     */
    @Override
    public void configure(Map<String,?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        logger.debug("KafkaStaticAuthenticationHandler.configure() called for " + saslMechanism);

        // A list of static users can be defined using a property
        String staticCredentialString = (String) configs.get(AUTH_STATIC_CREDENTIALS);
        if (staticCredentialString != null) {
            Map<String,AuthenticationCredential> parsedUserList = parseUserList(staticCredentialString);
            staticCredentials.putAll(parsedUserList);
        }

/*
        for (AppConfigurationEntry entry : jaasConfigEntries) {
            logger.info("JAAS Entry: " + entry.getLoginModuleName() + " (" + entry.getControlFlag() + ")");


            // Parse the username and password information from the JAAS entry
            if (entry.getOptions() != null) {
                String username = null;
                String password = null;
                for (String key : entry.getOptions().keySet()) {
                    if (key.equalsIgnoreCase(JAAS_CONFIG_USERNAME)) {
                        username = (String) entry.getOptions().get(key);
                    } else if (key.equalsIgnoreCase(JAAS_CONFIG_PASSWORD)) {
                        password = (String) entry.getOptions().get(key);
                    } else if (key.startsWith(JAAS_CONFIG_USER_PREFIX)) {
                        String altUser = key.substring(JAAS_CONFIG_USER_PREFIX.length());
                        String altPass = (String) entry.getOptions().get(key);
                        logger.info("JAAS alternate user: " + altUser);
                        jaasCredentials.put(altUser, altPass);
                    } else {
                        logger.warn("JAAS unknown option: " + key);
                    }
                }

                // Set the default username and password
                if (username != null) {
                    logger.info("JAAS primary user: " + username);
                    jaasCredentials.put(username, password);
                }
            }

        }
*/

    }

    @Override
    public void close() {
        logger.info("KafkaStaticAuthenticationHandler.close() called.");
    }

    @Override
    // See https://docs.oracle.com/javase/8/docs/api/javax/security/auth/callback/CallbackHandler.html
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        logger.debug("KafkaStaticAuthenticationHandler.handle() starting...");
        for (Callback callback: callbacks) {
            logger.debug("KafkaStaticAuthenticationHandler.handle() callback: " + callback.toString());
        }

        // The username and password are provided as part of two different callbacks.
        // The NameCallback provides the username.
        // The PlainAuthenticateCallback provides the password.
        String username = null;
        String password = null;
        for (Callback callback: callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                if (nc.getName() != null) {
                    username = nc.getName();
                } else {
                    username = nc.getDefaultName();
                }
                logger.debug("KafkaStaticAuthenticationHandler.handle() name callback: " + username);
                if ((username == null) || (username.trim().length() == 0)) {
                    throw new IOException("Authentication username is null or empty.");
                }
            } else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback pc = (PlainAuthenticateCallback) callback;
                password = new String(pc.password());
                logger.debug("KafkaStaticAuthenticationHandler.handle() performing authentication: username=" + username + ", password=" + password);
                if ((password == null) || (password.trim().length() == 0)) {
                    throw new IOException("Authentication password is null or empty.");
                }

                // Once the username and password have been obtained, perform the authentication
                AuthenticationAttempt currentAttempt = authenticate(username, password);
                logger.debug("KafkaStaticAuthenticationHandler.handle() authentication complete: [" + currentAttempt.getStatus() + "] " + currentAttempt.getStatusMessage());
                pc.authenticated(currentAttempt.wasSuccessful());
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }

        logger.debug("KafkaStaticAuthenticationHandler.handle() completed.");
    }

    /**
     * Attempt to authenticate the user against LDAP.
     *
     * @param username  LDAP username
     * @param password  LDAP password
     */
    private AuthenticationAttempt authenticate(String username, String password) {
        AuthenticationAttempt currentAttempt = null;

        // Attempt to authenticate using static credentials before attempting the LDAP server
        if ((staticCredentials != null) && (username != null)) {
            if (!staticCredentials.containsKey(username)) {
                AuthenticationCredential credentials = new AuthenticationCredential(username, password);
                currentAttempt = new AuthenticationAttempt(credentials);
                currentAttempt.setStatus(AuthenticationStatus.FAILURE);
                currentAttempt.setStatusMessage("Not a valid username: " + username);
            } else {
                AuthenticationCredential expectedCredential = staticCredentials.get(username);
                AuthenticationCredential actualCredential = new AuthenticationCredential(username, password, expectedCredential.getPasswordSalt());
                currentAttempt = new AuthenticationAttempt(actualCredential);

                boolean passwordsMatch = expectedCredential.matchesPassword(password, expectedCredential.getPasswordSalt());
                if (passwordsMatch) {
                    currentAttempt.setStatus(AuthenticationStatus.SUCCESS);
                    currentAttempt.setStatusMessage("Successfully authenticated username: " + username);
                } else {
                    currentAttempt.setStatus(AuthenticationStatus.FAILURE);
                    currentAttempt.setStatusMessage("Password does not match for username: " + username);
                }
            }
        }
        // Set the end date of the attempt so that an elapsed time can be calculated
        currentAttempt.setEndDate(new Date());

        // Log the attempt regardless of whether it was from the cache or from LDAP
        AuthenticationLogger.log(currentAttempt);

        return currentAttempt;
    }

    
}
