package de.upb.crypto.craco.common.interfaces.pe;

/**
 * Defines who gets to decrypt which ciphertexts.
 * See PredicateEncryptionScheme.
 *
 * @author Jan
 */
public interface Predicate {
    boolean check(KeyIndex kind, CiphertextIndex cind);
}
