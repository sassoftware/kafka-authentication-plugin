/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

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
 *     com.sas.kafka.auth.KafkaAuthenticationHandler
 * </code></blockquote>
 */
public class KafkaAuthenticationHandler implements AuthenticateCallbackHandler {
    private static final Logger logger = LoggerFactory.getLogger(KafkaAuthenticationHandler.class);

    /** Kafka property specifying the LDAP server URL */
    public static final String AUTH_LDAP_SERVER_URL = "auth.ldap.server.url";

    /** Kafka property specifying the LDAP bind DN for the account used to query LDAP */
    public static final String AUTH_LDAP_BIND_DN = "auth.ldap.bind.dn";

    /** Kafka property specifying the LDAP bind password for the account used to query LDAP */
    public static final String AUTH_LDAP_BIND_PASSWORD = "auth.ldap.bind.password";

    /** Kafka property specifying the LDAP field used to identify a username */
    public static final String AUTH_LDAP_ACCOUNTNAME_FIELD = "auth.ldap.user.id";

    /** Kafka property specifying whether to enable an authentication cache */
    public static final String AUTH_CACHE_ENABLED = "auth.cache.enabled";

    /** Kafka property specifying the maximum number of authentication attempts to keep in the cache */
    private static final String AUTH_CACHE_HISTORY_MAXDEPTH = "auth.cache.history.maxDepth";

    /** Kafka property specifying the maximum age of authentication attempts to keep in the cache */
    public static final String AUTH_CACHE_HISTORY_MAXAGE = "auth.cache.history.maxAge";

    /**
     * Singleton instance of the LDAP server and configuration.
     */
    private static LDAPServer server = null;

    /**
     * Singleton instance of an authentication cache to keep track of authentication
     * attempt history and protect the LDAP server from locking users out.
     */
    private static AuthenticationCache cache = new AuthenticationCache();

    /**
     * Boolean indicating whether the authentication cache is enabled or disabled.
     */
    private static boolean cacheEnabled = false;

    /**
     * Random salt used to hash passwords.  Since password hashing only matters
     * for the purposes of caching, the salt can be regenerated each time this
     * class is initialized.  This salt should never be logged or stored on disk
     * with the hashed password to limit the likelihood of a password list being
     * brute-force attacked.
     */
    private byte[] cacheSalt = null;


    /**
     * Maximum age in milliseconds that the authentication cache entries remain valid.
     */
    private static int cacheAgeLimit = 10 * 60 * 1000;

    /**
     * Construct the LDAP Authentication handler.
     */
    public KafkaAuthenticationHandler() {
        // Initialize the salt with a random value
        cacheSalt = generateSalt();
    }

    /**
     * Generate a random salt value.
     *
     * @return Random salt
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return salt;
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
        logger.info("SSDEBUG: KafkaAuthenticationHandler.configure() called for " + saslMechanism);

        for (AppConfigurationEntry entry : jaasConfigEntries) {
            logger.info("SSDEBUG: JAAS Entry: " + entry.toString());
        }

        // Get the LDAP configuration values from the Kafka properties
        String url = (String) configs.get(AUTH_LDAP_SERVER_URL);
        if (url == null) {
            logger.error("LDAP Authentication handler property must not be null: " + AUTH_LDAP_SERVER_URL);
        } else if (url.trim().length() == 0) {
            logger.error("LDAP Authentication handler property must not be empty: " + AUTH_LDAP_SERVER_URL);
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_LDAP_SERVER_URL + " = " + url);
        }

        // Construct the LDAP server as soon as the URL is available
        // so that the server can be updated by later properties
        server = new LDAPServer(url);

        // Override any LDAP server fields
        String accountNameField = (String) configs.get(AUTH_LDAP_ACCOUNTNAME_FIELD);
        if (accountNameField == null) {
            logger.info("LDAP Authentication handler property is null: " + AUTH_LDAP_ACCOUNTNAME_FIELD + " (Default: " + server.getAccountNameField() + ")");
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_LDAP_ACCOUNTNAME_FIELD + " = " + accountNameField);
            server.setAccountNameField(accountNameField);
        }

        // Configure the bind credentials used to connect to the server and run queries
        String bindDn = (String) configs.get(AUTH_LDAP_BIND_DN);
        if (bindDn == null) {
            logger.error("LDAP Authentication handler property must not be null: " + AUTH_LDAP_BIND_DN);
        } else if (bindDn.trim().length() == 0) {
            logger.error("LDAP Authentication handler property must not be empty: " + AUTH_LDAP_BIND_DN);
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_LDAP_BIND_DN + " = " + bindDn);
        }

        String bindPass = (String) configs.get(AUTH_LDAP_BIND_PASSWORD);
        if (bindPass == null) {
            logger.error("LDAP Authentication handler property must not be null: " + AUTH_LDAP_BIND_PASSWORD);
        } else if (bindPass.trim().length() == 0) {
            logger.error("LDAP Authentication handler property must not be empty: " + AUTH_LDAP_BIND_PASSWORD);
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_LDAP_BIND_PASSWORD + " = " + bindPass);
        }

        // Get the cache configuration values from the Kafka properties
        String cacheStatus = (String) configs.get(AUTH_CACHE_ENABLED);
        if (cacheStatus == null) {
            logger.info("LDAP Authentication handler property is null: " + AUTH_CACHE_ENABLED + " (Default: " + cacheEnabled + ")");
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_CACHE_ENABLED + " = " + cacheStatus);
            cacheEnabled = Boolean.valueOf(cacheStatus);
        }

        String cacheDepth = (String) configs.get(AUTH_CACHE_HISTORY_MAXDEPTH);
        if (cacheDepth == null) {
            logger.info("LDAP Authentication handler property is null: " + AUTH_CACHE_HISTORY_MAXDEPTH + " (Default: " + cache.getMaxDepth() + ")");
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_CACHE_HISTORY_MAXDEPTH + " = " + cacheDepth);
            cache.setMaxDepth(Integer.parseInt(cacheDepth));
        }

        String cacheAge = (String) configs.get(AUTH_CACHE_HISTORY_MAXAGE);
        if (cacheAge == null) {
            logger.info("LDAP Authentication handler property is null: " + AUTH_CACHE_HISTORY_MAXAGE + " (Default: " + cacheAgeLimit + ")");
        } else {
            logger.info("LDAP Authentication handler property is set: " + AUTH_CACHE_HISTORY_MAXAGE + " = " + cacheAge);
            cacheAgeLimit = Integer.parseInt(cacheAge);
        }

        // Connect to the LDAP server using the bind credentials
        try {
            server.connect(bindDn, bindPass);
            logger.info("Established connection to LDAP server: " + url);
        } catch (LDAPException ex) {
            logger.error("Failed to connect to LDAP server using bind credentials: " + ex.getMessage());
        }
    }

    @Override
    public void close() {
        logger.info("KafkaAuthenticationHandler.close() called.");
    }

    @Override
    // See https://docs.oracle.com/javase/8/docs/api/javax/security/auth/callback/CallbackHandler.html
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() starting...");
        for (Callback callback: callbacks) {
            logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() callback: " + callback.toString());
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
                logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() name callback: " + username);
                if ((username == null) || (username.trim().length() == 0)) {
                    throw new IOException("Authentication username is null or empty.");
                }
            } else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback pc = (PlainAuthenticateCallback) callback;
                password = new String(pc.password());
                logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() performing authentication: username=" + username + ", password=" + password);
                if ((password == null) || (password.trim().length() == 0)) {
                    throw new IOException("Authentication password is null or empty.");
                }

                // Once the username and password have been obtained, perform the authentication
                AuthenticationAttempt currentAttempt = authenticate(username, password);
                logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() authentication complete: [" + currentAttempt.getStatus() + "] " + currentAttempt.getStatusMessage());
                pc.authenticated(currentAttempt.wasSuccessful());

            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }

        logger.info("SSDEBUG: KafkaAuthenticationHandler.handle() completed.");
    }

    /**
     * Attempt to authenticate the user against LDAP.
     *
     * @param username  LDAP username
     * @param password  LDAP password
     */
    private AuthenticationAttempt authenticate(String username, String password) {
        AuthenticationCredentials credentials = new AuthenticationCredentials(username, password, cacheSalt);
        AuthenticationAttempt currentAttempt = new AuthenticationAttempt(credentials);

        // Check the cache first to determine if the cached authentication can be used
        boolean authenticatedFromCache = false;
        if (cacheEnabled) {
            logger.info("SSDEBUG: KafkaAuthenticationHandler.authenticate() using cache...");
            AuthenticationAttempt lastAttempt = cache.getMostRecentAttempt(credentials);
            if ((lastAttempt != null) && (lastAttempt.getStartDate() != null)) {
                long lastAttemptTimestamp = lastAttempt.getStartDate().getTime();
                long currentTimestamp = currentAttempt.getStartDate().getTime();
                long delta = currentTimestamp - lastAttemptTimestamp;
                logger.info("SSDEBUG: KafkaAuthenticationHandler.authenticate() delta = " + delta);
                // Determine if the last value in the cache had expired
                if (delta < cacheAgeLimit) {
                    // Set the authentication status to the last value in the cache
                    authenticatedFromCache = true;
                    currentAttempt.setStatus(lastAttempt.getStatus());
                    currentAttempt.setStatusMessage("User authenticated from cache (formerly: " + lastAttempt.getStatusMessage() + ")");
                }
            } else {
                logger.info("SSDEBUG: KafkaAuthenticationHandler.authenticate() last attempt is null or no date available");
            }
        }

        // Authenticate against LDAP if the cache was not used
        if (!authenticatedFromCache) {
            try {
                logger.info("SSDEBUG: KafkaAuthenticationHandler.authenticate() attempting LDAP authentication...");
                // The case where the LDAP server is null (initialization failure) is handled by the
                // try/catch block catching the NullPointerException and treating it like a normal auth failure
                boolean authenticated = server.areCredentialsValid(username, password);
                logger.info("SSDEBUG: KafkaAuthenticationHandler.authenticate() LDAP returned authenticated = " + authenticated);
                if (authenticated) {
                    currentAttempt.setStatus(AuthenticationStatus.SUCCESS);
                    currentAttempt.setStatusMessage("Successfully authenticated against LDAP server.");
                } else {
                    currentAttempt.setStatus(AuthenticationStatus.FAILURE);
                    currentAttempt.setStatusMessage("Authenticated failed against LDAP server.");
                }
            } catch (Exception ex) {
                logger.error("SSDEBUG: Failed to authenticate user: " + username, ex);
                currentAttempt.setStatus(AuthenticationStatus.ERROR);
                currentAttempt.setStatusMessage(ex.getMessage());
            }

            // Add the attempt to the cache if caching is enabled
            if (cacheEnabled) {
                try {
                    cache.add(currentAttempt);
                } catch (AuthenticationCredentialsException ex) {
                    logger.error("Failed to add LDAP authentication attempt to the cache: " + ex.getMessage());
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
