/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This data object represents a username and password used to perform user
 * authentication.  The unencrypted password is not stored, but a checksum
 * of the password is saved so that it can be used to determine if two
 * credentials are identical.
 */
public class AuthenticationCredentials {

    /** Username provided by the client during the authentication attempt */
    private String username = null;

    /** Salt value used to hash the password */
    private byte[] passwordSalt = null;

    /** Hashed version of the password provided by the client during the authentication attempt */
    private byte[] encodedPassword = null;

    /**
     * Construct an authentication attempt.  This class will not store the
     * password for security, but it will create a hashed version to confirm
     * that a password attempt hasn't changed.  The salt value will be used
     * when hashing the password.
     *
     * @param username   Username provided by the client
     * @param password   Password provided by the client
     * @param salt       Salt used to encode the password
     */
    public AuthenticationCredentials(String username, String password, byte[] salt) {
        this.username = username;
        this.passwordSalt = salt;

        try {
            encodedPassword = encodePassword(salt, password);
        } catch (AuthenticationCredentialsException ex) {
            // Do nothing if the hashing algorithm is unavailable?
        }
    }

    /**
     * Returns TRUE if the password matches the checksum of the password used in
     * the authentication attempt.
     * 
     * @param password   Password to compare to the one used in the authentication attempt
     * @param salt       Salt used to encode the password
     * @return TRUE if the password matches what was used during the authentication attempt
     */
    public boolean matchesPassword(String password, byte[] salt) {
        try {
            byte[] questionablePassword = encodePassword(salt, password);
            return matchesEncodedPassword(questionablePassword);
        } catch (AuthenticationCredentialsException ex) {
        }

        return false;
    }

    /**
     * Returns TRUE if the password digest matches the digest of the password used in
     * the authentication attempt.
     * 
     * @param digest  Message digest of the password to compare to the one used in the authentication attempt
     * @return TRUE if the digest matches what was used during the authentication attempt
     */
    public boolean matchesEncodedPassword(byte[] digest) {
        if ((encodedPassword == null) && (digest == null)) {
            return true;
        } else if ((encodedPassword != null) && (digest != null)) {
            if (encodedPassword.length != digest.length) {
                return false;
            }

            // Compare each byte in the digest to determine if they match
            for (int idx = 0; idx < encodedPassword.length; idx++) {
                if (encodedPassword[idx] != digest[idx]) {
                    return false;
                }
            }
        } else {
            // One of the digests is null and therefore they don't match
            return false;
        }

        return true;
    }

    /**
     * Compare the two authentication credentials to determine if they should be
     * considered duplicate attempts.  Duplicate attempts have the same username
     * and password hash.
     *
     * @param credentials Authentication credentials to compare to
     * @return TRUE if the attempt is a duplicate of this object
     */
    public boolean isDuplicate(AuthenticationCredentials credentials) {
        if (!username.equals(credentials.getUsername())) {
            return false;
        }

        if (!matchesEncodedPassword(credentials.getEncodedPassword())) {
            return false;
        }

        return true;
    }

    /**
     * Get the username used in the authentication attempt.
     *
     * @return Username provided during the authentication attempt
     */
    public String getUsername() {
        return username;
    }

    /**
     * Return the salt value used when hashing the password.
     *
     * @return salt value
     */
    public byte[] getPasswordSalt() {
        return passwordSalt;
    }

    /**
     * Get the password digest of the password used in the authentication attempt.
     * Although this class does not store the password, the digest makes it possible
     * to determine if the same password is being used across different authentication
     * attempts.
     *
     * @return A byte array containing a message digest of the password
     */
    public byte[] getEncodedPassword() {
        return encodedPassword;
    }

    /**
     * Return the password digest as a base64 encoded string or null if the original
     * password was a null or empty string.
     *
     * @return Base64 encoded string or null
     */
    public String getEncodedPasswordAsString() {
        if ((encodedPassword != null) && (encodedPassword.length > 0)) {
            return Base64.getEncoder().encodeToString(encodedPassword);
        } else {
            return null;
        }
    }

    /**
     * Use a hashing function to combine the salt value with a password to produce
     * a value that can be used to represent the password without being able to
     * recover the original password.  The same salt and password value should
     * always return the same encoded byte array.
     * 
     * See also: https://www.baeldung.com/java-password-hashing
     *
     * @param salt       Salt combined with the password during encoding
     * @param password   Password value
     * @return Password encoded with a one-way hash algorithm
     * @throws AuthenticationCredentialsException if the encoding algorith is unavailable
     */
    public static byte[] encodePassword(byte[] salt, String password) throws AuthenticationCredentialsException {
        byte[] hashedPassword = null;

        if ((password != null) && (password.trim().length() > 0)) {
            try {
                // Generate a hashed password using SHA-512 (less secure)
                //MessageDigest md = MessageDigest.getInstance("SHA-512");
                //md.update(salt);
                //hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));

                // Generate a hashed password using PBKDF2 (more secure)
                int iterationCount = 65536;
                int keyLength = 128;
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                hashedPassword = factory.generateSecret(spec).getEncoded();
            } catch (Exception ex) {
                throw new AuthenticationCredentialsException("Unable to encode password:" + ex.getMessage(), ex);
            }
        }

        return hashedPassword;
    }

}
