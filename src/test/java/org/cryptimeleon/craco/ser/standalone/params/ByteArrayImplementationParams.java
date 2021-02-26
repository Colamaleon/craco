package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class ByteArrayImplementationParams {

    public static StandaloneTestParams get() {
        ByteArrayImplementation bai = new ByteArrayImplementation("THISISATESTSTRING".getBytes());
        return new StandaloneTestParams(bai.getClass(), bai);
    }
}
