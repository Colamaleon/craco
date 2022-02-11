package org.cryptimeleon.craco.commitment;

import java.util.Objects;

/**
 * Holds a key pair consisting of a trapdoor key, as well as an commitment key
 * */
public class TrapdoorCommitmentKeyPair<OpenValueType extends OpenValue, TrapdoorValueType extends TrapdoorValue> {

    private final OpenValueType commitmentKey;

    private final TrapdoorValueType trapdoorKey;

    public TrapdoorCommitmentKeyPair(OpenValueType openValue, TrapdoorValueType trapdoorValue) {
        commitmentKey = openValue;
        trapdoorKey = trapdoorValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrapdoorCommitmentKeyPair<?, ?> that = (TrapdoorCommitmentKeyPair<?, ?>) o;
        return Objects.equals(commitmentKey, that.commitmentKey) && Objects.equals(trapdoorKey, that.trapdoorKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitmentKey, trapdoorKey);
    }

}
