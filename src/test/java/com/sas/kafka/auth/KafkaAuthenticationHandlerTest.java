/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import org.junit.Test;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.AppConfigurationEntry;

import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;

public class KafkaAuthenticationHandlerTest {

    private static final String testUsername = "testuser";
    private static final String testPassword = "testpass";

    /**
     * Construct the Kafka authentication handler and perform some basic tests
     * on the available methods.
     */
    @Test
    public void testHandler() {
        // Construct the handler class and configure it
        KafkaAuthenticationHandler handler = new KafkaAuthenticationHandler();

        // Set the config settings for the handler
        String saslMechanism = null;
        List<AppConfigurationEntry> jaasConfig = new ArrayList<AppConfigurationEntry>();
        HashMap<String,String> handlerConfig = new HashMap<String, String>();
        handlerConfig.put(KafkaAuthenticationHandler.AUTH_LDAP_SERVER_URL, "ldap://foo:1234");
        handlerConfig.put(KafkaAuthenticationHandler.AUTH_CACHE_ENABLED, "true");
        handler.configure(handlerConfig, saslMechanism, jaasConfig);

        // Execute some callbacks
        NameCallback nameCallback = new NameCallback("Username:", testUsername);
        PlainAuthenticateCallback authCallback = new PlainAuthenticateCallback(testPassword.toCharArray());

        Callback[] callbacks = new Callback[2];
        callbacks[0] = nameCallback;
        callbacks[1] = authCallback;
        try {
            handler.handle(callbacks);
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("Failed invoking callbacks: " + ex.getMessage());
        }
    }

}
