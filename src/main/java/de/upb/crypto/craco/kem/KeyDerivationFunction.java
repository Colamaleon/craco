package de.upb.crypto.craco.kem;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Takes key material and derives something from it
 * (typically a symmetric key).
 *
 * @param <T> type of the resulting derived key
 *
 */
public interface KeyDerivationFunction<T> extends StandaloneRepresentable {
    T deriveKey(KeyMaterial material);
}
