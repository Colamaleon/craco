package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.enc.*;

public class RepresentationTestParams {
    protected EncryptionScheme scheme;
    protected EncryptionKey encryptionKey;
    protected DecryptionKey decryptionKey;
    protected PlainText plainText;
    protected CipherText cipherText;
    protected MasterSecret masterSecret;

    public RepresentationTestParams(EncryptionScheme scheme, EncryptionKey encryptionKey, DecryptionKey decryptionKey,
                                    PlainText plainText, CipherText cipherText, MasterSecret masterSecret) {
        super();
        this.scheme = scheme;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
        this.plainText = plainText;
        this.cipherText = cipherText;
        this.masterSecret = masterSecret;
    }


    public String toString() {
        return scheme.getClass().getName();
    }
}
