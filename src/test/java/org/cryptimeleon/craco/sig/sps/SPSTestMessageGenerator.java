package org.cryptimeleon.craco.sig.sps;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.structures.groups.Group;

import java.util.stream.IntStream;

/**
 * A utility class that provides methods to generate test messages.
 */
public class SPSTestMessageGenerator {

    /**
     * Generates a plaintext consisting of a single random group element
     * @param targetGroup the group in which the generated plaintext should live
     * @return a {@link GroupElementPlainText} consisting of a single random group element in {@param targetGroup}
     */
    public static GroupElementPlainText generateGroupElementPlainText(Group targetGroup) {
        return new GroupElementPlainText(targetGroup.getUniformlyRandomElement());
    }

    /**
     * Generates a plaintext holding the neutral element of {@param targetGroup}
     * @param targetGroup the group in which the generated plaintext should live
     * @return a {@link GroupElementPlainText} holding the neutral element of {@param targetGroup}
     */
    public static GroupElementPlainText generateNeutralGroupElementPlainText(Group targetGroup) {
        return new GroupElementPlainText(targetGroup.getNeutralElement());
    }

    /**
     * Generates a plaintext consisting of a set of random group elements
     * @param targetGroup the group in which the generated group elements should live
     * @param numElements the intended size of the generated {@link MessageBlock}
     * @return a {@link MessageBlock} consisting of multiple {@link GroupElementPlainText}s in {@param targetGroup}
     */
    public static MessageBlock generateGroupElementMessageBlock(Group targetGroup, int numElements) {
        return new MessageBlock(
                IntStream.range(0, numElements).mapToObj(
                        x -> generateGroupElementPlainText(targetGroup)
                ).toArray(GroupElementPlainText[]::new)
        );
    }

    /**
     * Generates a plaintext consisting of {@param numElements} instances of the neutral element of {@param targetGroup}
     * @param targetGroup the group in which the generated group elements should live
     * @param numElements the intended size of the generated {@link MessageBlock}
     * @return a {@link MessageBlock} consisting of multiple instances of the neutral element of {@param targetGroup}
     */
    public static MessageBlock generateNeutralGroupElementMessageBlock(Group targetGroup, int numElements) {
        return new MessageBlock(
                IntStream.range(0, numElements).mapToObj(
                        x -> generateNeutralGroupElementPlainText(targetGroup)
                ).toArray(GroupElementPlainText[]::new)
        );
    }

    /**
     * Generates a {@link MessageBlock} of {@link GroupElementPlainText} where each of its group elements w_i
     *      differs from its corresponding m_i in {@param original}. The generated message block will have the same
     *      length as the original {@link MessageBlock} and will have group elements in the same group.
     * @param original the original {@link MessageBlock} to check against
     */
    public static MessageBlock generateWrongMessageBlock(MessageBlock original) {

        // check if these are valid parameters

        if(original.length() < 1) {
            throw new IllegalArgumentException("The original message block needs to hold at least one plaintext");
        }

        for (int i = 0; i < original.length(); i++) {
            if(!(original.get(i) instanceof GroupElementPlainText)) {
                throw new IllegalArgumentException("The original message block may only hold group elements");
            }
        }

        // if so, generate a message block based on the original

        GroupElementPlainText[] wrongMessage = new GroupElementPlainText[original.length()];

        for (int i = 0; i < original.length(); i++) {
            do {
                wrongMessage[i] = generateGroupElementPlainText(((GroupElementPlainText)original.get(i)).get().getStructure());
            }while(
                    wrongMessage[i].equals(((GroupElementPlainText)original.get(i)).get())
            );
        }

        return new MessageBlock(wrongMessage);
    }


    /**
     * Generates a messageBlock containing no plaintexts at all.
     */
    public static MessageBlock generateEmptyMessageBlock() {
        return new MessageBlock();
    }

    


}
