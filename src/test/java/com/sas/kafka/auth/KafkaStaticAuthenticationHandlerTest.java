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

public class KafkaStaticAuthenticationHandlerTest {

    private static final String testUsername = "testuser";
    private static final String testPassword = "testpass";

    private static final AuthenticationCredential testCredential = new AuthenticationCredential(testUsername, testPassword);

    /**
     * Construct a list of static authentication configuration settings.
     */
    private Map<String,String> createConfig() {
        Map<String,String> config = new HashMap<String,String>();

        config.put(KafkaStaticAuthenticationHandler.AUTH_STATIC_CREDENTIALS, testCredential.toString());

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
    private boolean authenticate(KafkaStaticAuthenticationHandler handler, String username, String password)
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
    private KafkaStaticAuthenticationHandler createHandler() {
        KafkaStaticAuthenticationHandler handler = new KafkaStaticAuthenticationHandler();

        // Set the config settings for the handler
        Map<String,String> handlerConfig = createConfig();
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
        KafkaStaticAuthenticationHandler handler = createHandler();

        // Perform an authentication attempt for the test user
        try {
            // Authentication should fail because the test user is not in the list of static credentials
            boolean authSuccess = authenticate(handler, testUsername, testPassword);
            assertTrue("Invalid user credentials: " + testUsername, authSuccess);
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Failed invoking callbacks: " + ex.getMessage());
        }
    }

}
