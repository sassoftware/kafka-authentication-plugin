/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * This is a command-line utility class used to get username and password
 * information from the user and convert it into strings that can be stored
 * in a file. 
 */
public class AuthenticationCredentialCmdLine {

    /** A prompt prefix is used to indent the user prompt from the left margin */
    private static String PROMPT_PREFIX = "   ";

    /** Ask they user for a username */
    private static String PROMPT_FOR_USERNAME = "Enter username:";

    /** Ask they user for a password */
    private static String PROMPT_FOR_PASSWORD = "Enter password:";

    /** Ask the user if they would like to enter more user credentials */
    private static String PROMPT_FOR_MORE_USERS = "Would you like to encode another user? (y/n)";

    public static void main (String[] args) {
        System.out.println("\nSpecify the username and password you would like to encode:\n");
        Collection<AuthenticationCredential> credentials = promptForCredentials();

        StringBuffer buffer = new StringBuffer();
        for (AuthenticationCredential credential : credentials) {
            if (!buffer.isEmpty()) {
                buffer.append(" ");
            }
            buffer.append(credential.toString());
        }

        System.out.println("\nPlace this credential string in the Kafka property file for later use:\n");
        System.out.println("   auth.static.credentials = \"" + buffer.toString() + "\"");
        System.out.println("");
    }

    /**
     * Display a prompt to the user.
     *
     * @param prompt Text to display to the user
     */
    private static void printPrompt(String prompt) {
        System.out.print(PROMPT_PREFIX + prompt + " ");
    }

    /**
     * Display an error message to the user.
     *
     * @param message Text to display to the user
     */
    private static void printPromptError(String message) {
        System.out.println(PROMPT_PREFIX + "ERROR: " + message);
    }

    /**
     * Prompt the user for the account credentials and return the list of users.
     *
     * @return List of credentials entered by the user
     */
    private static Collection<AuthenticationCredential> promptForCredentials() {
        Map<String, AuthenticationCredential> credentials = new HashMap<String, AuthenticationCredential>();

        Scanner input = new Scanner(System.in);
        boolean promptForInput = true;
        while (promptForInput) {
            // Continuously prompt for a valid username
            boolean validUsername = false;
            String username = null;
            while (!validUsername) {
                printPrompt(PROMPT_FOR_USERNAME);
                username = input.nextLine();
                if ((username == null) || (username.length() == 0)) {
                    validUsername = false;
                    printPromptError("Username cannot be empty.");
                } else if (credentials.containsKey(username)) {
                    validUsername = false;
                    printPromptError("That username was previously entered.");
                } else {
                    validUsername = true;
                }
            }

            // Continuously prompt for a valid password
            boolean validPassword = false;
            String password = null;
            while (!validPassword) {
                printPrompt(PROMPT_FOR_PASSWORD);
                password = input.nextLine();
                if ((password == null) || (password.length() == 0)) {
                    validPassword = false;
                    printPromptError("Password cannot be empty.");
                } else {
                    validPassword = true;
                }
            }

            // Encode the credentials as a string and add it to the buffer
            AuthenticationCredential credential = new AuthenticationCredential(username, password);
            credentials.put(username, credential);

            // Ask the user if they would like to encode another user
            System.out.println("\n");
            printPrompt(PROMPT_FOR_MORE_USERS);
            String moreUsersResponse = input.nextLine();
            switch (moreUsersResponse) {
                case "y":
                    promptForInput = true;
                    break;
                case "n":
                    promptForInput = false;
                    break;
                default:
                    printPrompt(PROMPT_FOR_MORE_USERS);
            }

            System.out.println("");
        }
        input.close();

        return credentials.values();
    }
}

