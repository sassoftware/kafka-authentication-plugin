/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.server.authorizer.AclCreateResult;
import org.apache.kafka.server.authorizer.AclDeleteResult;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.Authorizer;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements the Kafka Authorizer interface, which is used to allow
 * or deny access to a Kafka user following authentication.  As per the JavaDoc
 * for the Authorizer interface, the sequence of events for this class are:
 * 
 * <ol>
 *   <li>The broker initializes the Authorizer on startup based on the <code>authorizer.class.name</code> property.</li>
 *   <li>The broker configures and starts the Authorizer instance.  The Authorizer starts loading its metadata.</li>
 *   <li>The broker starts accepting connections and processing requests.</li>
 *   <li>For each listener, the socket waits for Authorization metadata to become available before accepting connections.</li>
 *   <li>For each connection, the broker performs authentication and then accepts Kafka requests.</li>
 * </ol>
 * 
 * For reference:
 * 
 * <ul>
 *   <li>org.apache.kafka.metadata.authorizer.StandardAuthorizer</li>
 *   <li></li>
 * </ul>
 * 
 * Additional notes:
 * 
 * <ul>
 *   <li>
 *     Authorizer implementation class may optionally implement @Reconfigurable to enable
 *     dynamic reconfiguration without restarting the broker
 *   </li>
 *   <li>All authorizer operations including authorization and ACL updates must be thread-safe.</li>
 *   <li>
 *     ACL update methods are asynchronous. Implementations with low update latency may return
 *     a completed future using CompletableFuture.completedFuture(Object). This ensures that
 *     the request will be handled synchronously by the caller without using a purgatory to wait
 *     for the result. If ACL updates require remote communication which may block, return a
 *     future that is completed asynchronously when the remote operation completes. This enables
 *     the caller to process other requests on the request threads without blocking
 *   </li>
 *   <li>
 *     Any threads or thread pools used for processing remote operations asynchronously can be
 *     started during start(AuthorizerServerInfo). These threads must be shutdown during Closeable.close().
 *   </li>
 * </ul>
 */
public class KafkaAuthorizer implements Authorizer {
    private static final Logger logger = LoggerFactory.getLogger(KafkaAuthorizer.class);

    /**
     * Construct the Kafka authorizer class.
     */
    public KafkaAuthorizer() {
    }

    @Override

    public Map<Endpoint, ? extends CompletionStage<Void>> start(AuthorizerServerInfo serverInfo) {
        logger.info("KafkaAuthorizer.start(): starting...");

        // Construct the list of endpoints that are known to the Kafka broker
        Map<Endpoint, CompletableFuture<Void>> result = new HashMap<>();
        for (Endpoint endpoint : serverInfo.endpoints()) {

            // TODO figure out how to process each endpoint and add it to the list of returned objects

            // Get the listener name for the endpoint, or an empty string if no name is defined
            String listenerName = endpoint.listenerName().orElse("");
            if (serverInfo.earlyStartListeners().contains(listenerName)) {
                logger.info("KafkaAuthorizer.start(): adding " + listenerName + " listener to the list of endpoints");
                result.put(endpoint, CompletableFuture.completedFuture(null));
            } else {
                logger.info("KafkaAuthorizer.start(): skipping " + listenerName + " listener instead of adding it to the list of endpoints");
                //result.put(endpoint, initialLoadFuture);
            }
        }

        logger.info("KafkaAuthorizer.start(): completed.");
        return result;
    }

    @Override
    public List<AuthorizationResult> authorize(AuthorizableRequestContext requestContext, List<Action> actions) {
        logger.info("KafkaAuthorizer.authorize() starting...");

        List<AuthorizationResult> results = new ArrayList<>(actions.size());
        for (Action action : actions) {

            // TODO figure out how to check the action and authorize the request

            logger.info("KafkaAuthorizer.authorize() processing action " + action);
            results.add(AuthorizationResult.DENIED);
        }

        logger.info("KafkaAuthorizer.authorize() completed.");
        return results;
    }

    @Override
    public List<? extends CompletionStage<AclCreateResult>> createAcls(AuthorizableRequestContext requestContext, List<AclBinding> aclBindings) {
        logger.info("KafkaAuthorizer.createAcls() starting...");

        List<CompletableFuture<AclCreateResult>> futures = new ArrayList<>(aclBindings.size());

        // TODO figure out how to create ACLs

        logger.info("KafkaAuthorizer.createAcls() completed.");
        return futures;
    }

    @Override
    public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(AuthorizableRequestContext requestContext, List<AclBindingFilter> aclBindingFilters) {
        logger.info("KafkaAuthorizer.deleteAcls() starting...");

        List<CompletableFuture<AclDeleteResult>> futures = new ArrayList<>(aclBindingFilters.size());

        // TODO figure out how to delete ACLs

        logger.info("KafkaAuthorizer.deleteAcls() completed.");
        return futures;
    }

    @Override
    public Iterable<AclBinding> acls(AclBindingFilter filter) {
        logger.info("KafkaAuthorizer.acls() called.");
        return null;
    }

    @Override
    public void configure(Map<String, ?> configs) {
        
        // TODO get a kafka config property which points to the ldap config file

        logger.info("KafkaAuthorizer.configure() called.");
    }

    @Override
    public void close() {
        logger.info("KafkaAuthorizer.close() called.");
    }

}
