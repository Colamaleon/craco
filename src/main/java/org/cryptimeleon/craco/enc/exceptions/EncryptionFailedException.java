package org.cryptimeleon.craco.enc.exceptions;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Exception thrown when encryption fails.
 */
public class EncryptionFailedException extends GeneralFailedException {

    private static final long serialVersionUID = 1941422593845103555L;

    public EncryptionFailedException(GeneralSecurityException e, String cause) {
        super(e, cause);
    }

    public EncryptionFailedException(IOException e, String localizedMessage) {
        super(e, localizedMessage);
    }


}
