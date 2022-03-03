package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * A signature as generated by the SPS scheme {@link SPSXSIGSignatureScheme}.
 *
 */
public class SPSXSIGSignature implements Signature, UniqueByteRepresentable {

    /**
     * S^{tilde}_0 \in G_2 in the paper
     */
    @UniqueByteRepresented
    @Represented(restorer = "G2")
    protected GroupElement group2ElementSigma0;

    /**
     * S_i \in G_1 in the paper, i \in [1,5]
     */
    @UniqueByteRepresented
    @Represented(restorer = "[G1]")
    protected GroupElement[] group1ElementsSigma;


    public SPSXSIGSignature(Representation repr, Group G1, Group G2) {
        new ReprUtil(this).register(G1, "G1").register(G2, "G2"). deserialize(repr);
    }

    public SPSXSIGSignature(GroupElement group2ElementSigma0, GroupElement[] group1ElementsSigma) {

        //check if group1ElementsSigma has the appropriate amount of elements
        if(group1ElementsSigma.length != 5) {
            throw new IllegalArgumentException("The signature requires exactly 5 G1-GroupElements, but got: "
                    + group1ElementsSigma.length);
        }

        this.group2ElementSigma0 = group2ElementSigma0;
        this.group1ElementsSigma = group1ElementsSigma;
    }


    public GroupElement getGroup2ElementSigma0() {
        return group2ElementSigma0;
    }


    public GroupElement[] getGroup1ElementsSigma() {
        return group1ElementsSigma;
    }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSXSIGSignature that = (SPSXSIGSignature) o;
        return Objects.equals(group2ElementSigma0, that.group2ElementSigma0)
                && Arrays.equals(group1ElementsSigma, that.group1ElementsSigma);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(group2ElementSigma0);
        result = 31 * result + Arrays.hashCode(group1ElementsSigma);
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
