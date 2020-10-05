// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.crypto.examples;

import com.amazonaws.encryptionsdk.TestUtils;
import com.amazonaws.encryptionsdk.kms.AwsKmsCmkId;
import com.amazonaws.encryptionsdk.kms.KMSTestFixtures;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestFactory;
import org.junit.platform.commons.support.HierarchyTraversalMode;
import org.junit.platform.commons.support.ReflectionSupport;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

@Tag(TestUtils.TAG_INTEGRATION)
class ExamplesTest {

    private static final Logger LOGGER = Logger.getLogger(ExamplesTest.class.getName());
    private static final String RUN_METHOD_NAME = "run";
    private static final String TEST_CLASS_SUFFIX = "Test";
    private static final byte[] STATIC_PLAINTEXT = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
            "Praesent non feugiat leo. Aenean iaculis tellus ut velit consectetur, " +
            "quis convallis orci eleifend. Sed eu dictum sapien. Nulla facilisi. Suspendisse potenti. " +
            "Proin vehicula vehicula maximus. Donec varius et elit vel rutrum. Nulla lacinia neque turpis," +
            " quis consequat orci pharetra et. Etiam consequat ullamcorper mauris. Vivamus molestie mollis " +
            "mauris a gravida. Curabitur sed bibendum nisl. Cras varius tortor non erat sodales, quis congue" +
            " tellus laoreet. Etiam fermentum purus eu diam sagittis, vitae commodo est vehicula. " +
            "Nulla feugiat viverra orci vel interdum. Quisque pulvinar elit eget nulla facilisis varius. " +
            "Mauris at suscipit sem. Aliquam in purus ut velit fringilla volutpat id non mi. " +
            "Curabitur quis nunc eleifend, ornare lectus non, fringilla quam. Nam maximus volutpat placerat. " +
            "Nulla ullamcorper lorem velit, nec sagittis ex tristique posuere. Aliquam fringilla magna commodo" +
            " libero faucibus tempor. Vestibulum non ligula tincidunt, finibus sapien in, sollicitudin " +
            "ex. Pellentesque congue laoreet mi in condimentum. Cras convallis nisi ac nunc tincidunt " +
            "venenatis. Suspendisse urna elit, cursus eu lacus a, aliquet porttitor mi. " +
            "Nulla vel congue nibh, sed condimentum dui. Ut ante ligula, blandit eu finibus nec, " +
            "scelerisque quis eros. Maecenas gravida odio eget nibh dictum, dictum varius lacus interdum. " +
            "Integer quis nulla vulputate, rhoncus diam vitae, mollis mauris. Sed ut porttitor dolor. " +
            "Fusce ut justo a ex bibendum imperdiet nec sit amet magna. Sed ullamcorper luctus augue, " +
            "tempor viverra elit interdum sed. Cras sit amet arcu eu turpis molestie sollicitudin. " +
            "Curabitur fermentum varius nibh, ut aliquet nisi. Aliquam id tempus tellus. " +
            "Nulla porttitor nulla at nibh interdum, quis sollicitudin erat egestas. " +
            "Ut blandit mauris quis efficitur efficitur. Morbi neque sapien, posuere ut aliquam eget, " +
            "aliquam at velit. Morbi sit amet rhoncus felis, et hendrerit sem. Nulla porta dictum ligula " +
            "eget iaculis. Cras lacinia ligula quis risus ultrices, sed consectetur metus imperdiet. " +
            "Nullam id enim vestibulum nibh ultricies auctor. Morbi neque lacus, faucibus vitae commodo quis, " +
            "malesuada sed velit.").getBytes(StandardCharsets.UTF_8);

    @TestFactory
    Stream<DynamicTest> testExamples() {
        final List<Class<?>> exampleClasses = ReflectionSupport.findAllClassesInPackage(getClass().getPackage().getName(),
                c -> Arrays.stream(c.getDeclaredMethods()).anyMatch(m -> m.getName().equals(RUN_METHOD_NAME)),
                c -> !c.endsWith(TEST_CLASS_SUFFIX));

        return exampleClasses.stream()
                .map(c -> ReflectionSupport.findMethods(c, m -> m.getName().equals(RUN_METHOD_NAME), HierarchyTraversalMode.TOP_DOWN).get(0))
                .map(ExamplesTest::createTest);
    }

    /**
     * Creates a DynamicTest for the given method, matching each parameter type
     * to the 4 parameter types that we have predefined values for.
     */
    private static DynamicTest createTest(Method method) {
        final Class<?>[] parameterTypes = method.getParameterTypes();
        final Object[] parameterValues = new Object[parameterTypes.length];

        for (int i = 0; i < parameterTypes.length; i++) {
            if (parameterTypes[i].isAssignableFrom(AwsKmsCmkId.class)) {
                parameterValues[i] = AwsKmsCmkId.fromString(KMSTestFixtures.TEST_KEY_IDS[0]);
            } else if (parameterTypes[i].isAssignableFrom(List.class)) {
                parameterValues[i] = Arrays.asList(AwsKmsCmkId.fromString(KMSTestFixtures.TEST_KEY_IDS[0]), AwsKmsCmkId.fromString(KMSTestFixtures.TEST_KEY_IDS[1]));
            } else if (parameterTypes[i].isAssignableFrom(byte[].class)) {
                parameterValues[i] = STATIC_PLAINTEXT;
            } else if (parameterTypes[i].isAssignableFrom(File.class)) {
                try {
                    final File tempFile = File.createTempFile(method.getDeclaringClass().getSimpleName(), ".tmp");
                    tempFile.deleteOnExit();

                    try (OutputStream os = Files.newOutputStream(tempFile.toPath())) {
                        os.write(STATIC_PLAINTEXT);
                    }

                    parameterValues[i] = tempFile;
                } catch (IOException e) {
                    fail("Failed to create temp file", e);
                }
            } else {
                LOGGER.info(String.format("Setting unsupported parameter type[%s] to null", parameterTypes[i]));
                parameterValues[i] = null;
            }
        }

        return DynamicTest.dynamicTest(method.getDeclaringClass().getName(), () -> {
            try {
                method.invoke(null, parameterValues);
            } catch (IllegalAccessException e) {
                fail(method.getDeclaringClass().getName() + " failed", e);
            } catch (InvocationTargetException e) {
                fail(method.getDeclaringClass().getName() + " failed", e.getCause());
            }
        });
    }

}
