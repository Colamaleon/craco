package de.upb.crypto.craco.common.interfaces;


/**
 * A standard public-key encryption scheme.
 * <p>
 * Encryption can be done via the public key and decryption via the secret key.
 *
 * @author Jan
 */
public interface AsymmetricEncryptionScheme extends EncryptionScheme {

    /**
     * Generates the key pair consisting of public and secret key.
     */
    KeyPair generateKeyPair();

}
