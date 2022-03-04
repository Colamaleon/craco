package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Objects;


/**
 * A signing key as generated by the {@link SPSXSIGSignatureScheme}.
 *
 * Note: V6 is part of the verification key, but as it is used for signature calculation, the groupElement
 *      is also stored here.
 */
public class SPSXSIGSigningKey implements SigningKey {

    /**
     * K_1 \in G_1 in the paper
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementK1;

    /**
     * K_2 \in G_1 in the paper
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementK2;

    /**
     * K_3 \in G_1 in the paper
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementK3;

    /**
     * K_4 \in G_1 in the paper
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementK4;

    /**
     * V^{tilde}_6 \in G_2 in the paper
     * Note: V6 is part of the verification key, but as it is used for signature calculation, the groupElement
     *      is also stored here.
     * */
    @Represented(restorer = "G2")
    protected GroupElement group2ElementV6;


    public SPSXSIGSigningKey(GroupElement group2ElementV6,
                             GroupElement group1ElementK1,
                             GroupElement group1ElementK2,
                             GroupElement group1ElementK3,
                             GroupElement group1ElementK4) {

        this.group1ElementK1 = group1ElementK1;
        this.group1ElementK2 = group1ElementK2;
        this.group1ElementK3 = group1ElementK3;
        this.group1ElementK4 = group1ElementK4;
        this.group2ElementV6 = group2ElementV6;
    }

    public SPSXSIGSigningKey(Group G1, Group G2, Representation repr){
        new ReprUtil(this).register(G1, "G1").register(G2, "G2").deserialize(repr);
    }


    public GroupElement getGroup1ElementK1() {
        return group1ElementK1;
    }

    public GroupElement getGroup1ElementK2() {
        return group1ElementK2;
    }

    public GroupElement getGroup1ElementK3() {
        return group1ElementK3;
    }

    public GroupElement getGroup1ElementK4() {
        return group1ElementK4;
    }

    public GroupElement getGroup2ElementV6() {
        return group2ElementV6;
    }


    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSXSIGSigningKey that = (SPSXSIGSigningKey) o;
        return Objects.equals(group1ElementK1, that.group1ElementK1)
                && Objects.equals(group1ElementK2, that.group1ElementK2)
                && Objects.equals(group1ElementK3, that.group1ElementK3)
                && Objects.equals(group1ElementK4, that.group1ElementK4)
                && Objects.equals(group2ElementV6, that.group2ElementV6);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group1ElementK1, group1ElementK2, group1ElementK3, group1ElementK4, group2ElementV6);
    }


}
