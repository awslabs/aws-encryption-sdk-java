package com.amazonaws.encryptionsdk;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

public class TestUtils {
    // avoid spending time generating random data on every test case by caching some random test vectors
    private static final AtomicReference<byte[]> RANDOM_CACHE = new AtomicReference<>(new byte[0]);

    private static byte[] ensureRandomCached(int length) {
        byte[] buf = RANDOM_CACHE.get();
        if (buf.length >= length) {
            return buf;
        }

        byte[] newBuf = new byte[length];
        ThreadLocalRandom.current().nextBytes(newBuf);

        return RANDOM_CACHE.updateAndGet(oldBuf -> {
            if (oldBuf.length < newBuf.length) {
                return newBuf;
            } else {
                return oldBuf;
            }
        });
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Throwable;
    }

    public static void assertThrows(Class<? extends Throwable> throwableClass, ThrowingRunnable callback) {
        try {
            callback.run();
        } catch (Throwable t) {
            if (throwableClass.isAssignableFrom(t.getClass())) {
                // ok
                return;
            }
        }

        fail("Expected exception of type " + throwableClass);
    }

    public static void assertThrows(ThrowingRunnable callback) {
        assertThrows(Throwable.class, callback);
    }

    /**
     * Asserts that substituting any argument with null causes a NPE to be thrown.
     *
     * Usage:
     * {@code
     *
     * assertNullChecks(
     *   myAwsCrypto,
     *   "createDecryptingStream",
     *   CryptoMaterialsManager.class, myCMM,
     *   InputStream.class, myIS
     * );
     * }
     * @param callee
     * @param methodName
     * @param args
     * @throws Exception
     */
    public static void assertNullChecks(
            Object callee,
            String methodName,
            // Class, value
            Object... args
    ) throws Exception {
        ArrayList<Class> parameterTypes = new ArrayList<>();
        for (int i = 0; i < args.length; i += 2) {
            parameterTypes.add((Class)args[i]);
        }

        Method m = callee.getClass().getMethod(methodName, parameterTypes.toArray(new Class[0]));

        for (int i = 0; i < args.length / 2; i++) {
            if (args[i * 2 + 1] == null) {
                // already null, which means null is ok here
                continue;
            }

            if (parameterTypes.get(i).isPrimitive()) {
                // can't be null
                continue;
            }

            Object[] modifiedArgs = new Object[args.length/2];
            for (int j = 0; j < args.length / 2; j++) {
                modifiedArgs[j] = args[j * 2 + 1];
                if (j == i) {
                    modifiedArgs[j] = null;
                }
            }

            try {
                m.invoke(callee, modifiedArgs);
                fail("Expected NullPointerException");
            } catch (InvocationTargetException e) {
                if (e.getCause().getClass() == NullPointerException.class) {
                    continue;
                }

                fail("Expected NullPointerException, got: " + e.getCause());
            }
        }
    }

    public static byte[] toByteArray(InputStream is) throws IOException {
        byte[] buffer = new byte[4096];

        int offset = 0;
        int rv;
        while (true) {
            rv = is.read(buffer, offset, buffer.length - offset);
            if (rv <= 0) {
                break;
            }

            offset += rv;

            if (offset == buffer.length) {
                if (buffer.length == Integer.MAX_VALUE) {
                    throw new IOException("Input data exceeds maximum array size");
                }

                int newSize = Math.toIntExact(Math.min(Integer.MAX_VALUE, 2L * buffer.length));

                byte[] newBuffer = new byte[newSize];
                System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
                buffer = newBuffer;
            }
        }

        return Arrays.copyOfRange(buffer, 0, offset);
    }

    public static byte[] insecureRandomBytes(int length) {
        byte[] buf = new byte[length];

        System.arraycopy(ensureRandomCached(length), 0, buf, 0, length);

        return buf;
    }

    public static ByteArrayInputStream insecureRandomStream(int length) {
        return new ByteArrayInputStream(ensureRandomCached(length), 0, length);
    }

    public static int[] getFrameSizesToTest(final CryptoAlgorithm cryptoAlg) {
      final int blockSize = cryptoAlg.getBlockSize();
      final int[] frameSizeToTest = {
          0,
          blockSize - 1,
          blockSize,
          blockSize + 1,
          blockSize * 2,
          blockSize * 10,
          blockSize * 10 + 1,
          AwsCrypto.getDefaultFrameSize()
      };
      return frameSizeToTest;
  }

    /**
     * Converts an array of unsigned bytes (represented as int values between 0 and 255 inclusive)
     * to an array of Java primitive type byte, which are by definition signed.
     *
     * @param unsignedBytes An array on unsigned bytes
     * @return An array of signed bytes
     */
    public static byte[] unsignedBytesToSignedBytes(final int[] unsignedBytes) {
        byte[] signedBytes = new byte[unsignedBytes.length];

        for (int i = 0; i < unsignedBytes.length; i++) {
            if (unsignedBytes[i] > 255) {
                throw new IllegalArgumentException("Encountered unsigned byte value > 255");
            }
            signedBytes[i] = (byte) (unsignedBytes[i] & 0xff);
        }

        return signedBytes;
    }

    /**
     * Converts an array of Java primitive type bytes (which are by definition signed) to
     * an array of unsigned bytes (represented as int values between 0 and 255 inclusive).
     *
     * @param signedBytes An array of signed bytes
     * @return An array of unsigned bytes
     */
    public static int[] signedBytesToUnsignedBytes(final byte[] signedBytes) {
        int[] unsignedBytes = new int[signedBytes.length];

        for (int i = 0; i < signedBytes.length; i++) {
            unsignedBytes[i] = ((int) signedBytes[i]) & 0xff;
        }

        return unsignedBytes;
    }
}
