package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;

public class SPSPOSSignature implements Signature, UniqueByteRepresentable {

    @Represented(restorer = "G2")
    protected GroupElement group2ElementZ;

    @Represented(restorer = "G2")
    protected GroupElement group2ElementR;



    public SPSPOSSignature(Representation repr, Group groupG2) {
        new ReprUtil(this).register(groupG2, "G2").deserialize(repr);
    }

    public SPSPOSSignature(GroupElement group2ElementZ, GroupElement group2ElementR) {
        this.group2ElementR = group2ElementR;
        this.group2ElementZ = group2ElementZ;
    }




    public GroupElement getGroup2ElementZ() {
        return group2ElementZ;
    }

    public GroupElement getGroup2ElementR() {
        return group2ElementR;
    }




    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSPOSSignature that = (SPSPOSSignature) o;
        return Objects.equals(group2ElementZ, that.group2ElementZ) && Objects.equals(group2ElementR, that.group2ElementR);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group2ElementZ, group2ElementR);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
