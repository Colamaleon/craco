package org.cryptimeleon.craco.enc.streaming;

import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.enc.StreamingEncryptionScheme;

public class StreamingEncryptionSchemeParams {

    private StreamingEncryptionScheme encryptionScheme;

    private KeyPair keyPair;

    public StreamingEncryptionSchemeParams(StreamingEncryptionScheme encryptionScheme, KeyPair keyPair) {
        this.encryptionScheme = encryptionScheme;
        this.keyPair = keyPair;
    }

    public StreamingEncryptionScheme getEncryptionScheme() {
        return encryptionScheme;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String toString() {
        return encryptionScheme.getClass().getName();
    }
}
