/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;

public class KafkaLdapAuthenticationHandlerTest {

    private static final String testUsername = "testuser";
    private static final String testPassword = "testpass";

    /**
     * Construct a list of LDAP configuration settings.
     */
    private Map<String,String> createLdapConfig() {
        Map<String,String> config = new HashMap<String,String>();

        config.put(KafkaLdapAuthenticationHandler.AUTH_LDAP_SERVER_URL, "ldap://foo:1234");
        config.put(KafkaLdapAuthenticationHandler.AUTH_CACHE_ENABLED, "true");

        return config;
    }

    /**
     * Construct the JAAS configuration settings.
     */
    private List<AppConfigurationEntry> createJaasConfig() {
        List<AppConfigurationEntry> jaasConfigList = new ArrayList<AppConfigurationEntry>();

        // Define the JAAS configuration values
        String loginModuleName = "com.sas.kafka.auth.SimpleLoginModule";
        AppConfigurationEntry.LoginModuleControlFlag controlFlag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
        HashMap<String,String> entryMap = new HashMap<String,String>();
        AppConfigurationEntry jaasConfigEntry = new AppConfigurationEntry(loginModuleName, controlFlag, entryMap);

        jaasConfigList.add(jaasConfigEntry);

        return jaasConfigList;
    }

    /**
     * Construct callbacks for the username and password and return the result.
     *
     * @param handler   Authentication callback handler used to perform authentication
     * @param username  Username to authenticate
     * @param password  Password to authenticate
     * @return TRUE if authentication was successful
     * @throws IOException If there is an error during the authentication callback
     * @throws UnsupportedCallbackException if the callback type cannot be handled
     */
    private boolean authenticate(KafkaLdapAuthenticationHandler handler, String username, String password)
        throws IOException, UnsupportedCallbackException
    {
        NameCallback nameCallback = new NameCallback("Username:", username);
        PlainAuthenticateCallback authCallback = new PlainAuthenticateCallback(password.toCharArray());

        Callback[] callbacks = new Callback[2];
        callbacks[0] = nameCallback;
        callbacks[1] = authCallback;
        handler.handle(callbacks);

        return authCallback.authenticated();
    }

    /**
     * Construct the authentication handler.
     *
     * @return an instance of the authentication handler
     */
    private KafkaLdapAuthenticationHandler createHandler() {
        KafkaLdapAuthenticationHandler handler = new KafkaLdapAuthenticationHandler();

        // Set the config settings for the handler
        Map<String,String> handlerConfig = createLdapConfig();
        String saslMechanism = null;
        List<AppConfigurationEntry> jaasConfigList = createJaasConfig();
        handler.configure(handlerConfig, saslMechanism, jaasConfigList);

        return handler;
    }

    /**
     * Construct the Kafka authentication handler and perform a basic test of
     * authentication using a username and password.
     */
    @Test
    public void testAuthenticationHandler() {
        // Construct the handler class and configure it
        KafkaLdapAuthenticationHandler handler = createHandler();

        // Perform an authentication attempt for the test user
        try {
            // Authentication should fail because the test user is not in the list of static credentials
            boolean validCredentials = authenticate(handler, testUsername, testPassword);
            assertFalse("Invalid user credentials: " + testUsername, validCredentials);
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Failed invoking callbacks: " + ex.getMessage());
        }
    }

}
