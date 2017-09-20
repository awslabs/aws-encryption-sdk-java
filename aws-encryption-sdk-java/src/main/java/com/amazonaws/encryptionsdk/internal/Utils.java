/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.internal;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Internal utility methods.
 */
public final class Utils {
    // SecureRandom objects can both be expensive to initialize and incur synchronization costs.
    // This allows us to minimize both initializations and keep SecureRandom usage thread local
    // to avoid lock contention.
    private static final ThreadLocal<SecureRandom> LOCAL_RANDOM = new ThreadLocal<SecureRandom>() {
      @Override
      protected SecureRandom initialValue() {
          final SecureRandom rnd = new SecureRandom();
          rnd.nextBoolean(); // Force seeding
          return rnd;
      }
    };

    private Utils() {
        // Prevent instantiation
    }

    /*
     * In some areas we need to be able to assign a total order over Java objects - generally with some primary sort,
     * but we need a fallback sort that always works in order to ensure that we don't falsely claim objects A and B
     * are equal just because the primary sort declares them to have equal rank.
     *
     * To do this, we'll define a fallback sort that assigns an arbitrary order to all objects. This order is
     * implemented by first comparing hashcode, and in the rare case where we are asked to compare two objects with
     * equal hashcode, we explicitly assign an index to them - using a WeakHashMap to track this index - and sort
     * based on this index.
     */
    private static AtomicLong FALLBACK_COUNTER = new AtomicLong(0);
    private static WeakHashMap<Object, Long> FALLBACK_COMPARATOR_MAP = new WeakHashMap<>();

    private static synchronized long getFallbackObjectId(Object object) {
        return FALLBACK_COMPARATOR_MAP.computeIfAbsent(object, ignored -> FALLBACK_COUNTER.incrementAndGet());
    }

    /**
     * Provides an <i>arbitrary</i> but consistent total ordering over all objects. This comparison function will
     * return 0 if and only if a == b, and otherwise will return arbitrarily either -1 or 1, but will do so in a way
     * that results in a consistent total order.
     *
     * @param a
     * @param b
     * @return -1 or 1 (consistently) if a != b; 0 if a == b.
     */
    public static int compareObjectIdentity(Object a, Object b) {
        if (a == b) {
            return 0;
        }

        if (a == null) {
            return -1;
        }

        if (b == null) {
            return 1;
        }

        int hashCompare = Integer.compare(System.identityHashCode(a), System.identityHashCode(b));
        if (hashCompare != 0) {
            return hashCompare;
        }

        // Unfortunately these objects have identical hashcodes, so we need to find some other way to compare them.
        // We'll do this by mapping them to an incrementing counter, and comparing their assigned IDs instead.
        int fallbackCompare = Long.compare(getFallbackObjectId(a), getFallbackObjectId(b));
        if (fallbackCompare == 0) {
            throw new AssertionError("Failed to assign unique order to objects");
        }

        return fallbackCompare;
    }

    public static long saturatingAdd(long a, long b) {
        long r = a + b;

        if (a > 0 && b > 0 && r < a) {
            return Long.MAX_VALUE;
        }

        if (a < 0 && b < 0 && r > a) {
            return Long.MIN_VALUE;
        }

        // If the signs between a and b differ, overflow is impossible.

        return r;
    }

    /**
     * Comparator that performs a lexicographical comparison of byte arrays, treating them as unsigned.
     */
    public static class ComparingByteArrays implements Comparator<byte[]>, Serializable {
        // We don't really need to be serializable, but it doesn't hurt, and FindBugs gets annoyed if we're not.
        private static final long serialVersionUID = 0xdf641037ffe509e2L;

        @Override public int compare(byte[] o1, byte[] o2) {
            return new ComparingByteBuffers().compare(ByteBuffer.wrap(o1), ByteBuffer.wrap(o2));
        }
    }

    public static class ComparingByteBuffers implements Comparator<ByteBuffer>, Serializable {
        private static final long serialVersionUID = 0xa3c4a7300fbbf043L;

        @Override public int compare(ByteBuffer o1, ByteBuffer o2) {
            o1 = o1.slice();
            o2 = o2.slice();

            int commonLength = Math.min(o1.remaining(), o2.remaining());

            for (int i = 0; i < commonLength; i++) {
                // Perform zero-extension as we want to treat the bytes as unsigned
                int v1 = o1.get(i) & 0xFF;
                int v2 = o2.get(i) & 0xFF;

                if (v1 != v2) {
                    return v1 - v2;
                }
            }

            // The longer buffer is bigger (0x00 comes after end-of-buffer)
            return o1.remaining() - o2.remaining();
        }
    }

    /**
     * Throws {@link NullPointerException} with message {@code paramName} if {@code object} is null.
     *
     * @param object
     *            value to be null-checked
     * @param paramName
     *            message for the potential {@link NullPointerException}
     * @return {@code object}
     * @throws NullPointerException
     *             if {@code object} is null
     */
    public static <T> T assertNonNull(final T object, final String paramName) throws NullPointerException {
        if (object == null) {
            throw new NullPointerException(paramName + " must not be null");
        }
        return object;
    }

    /**
     * Returns a possibly truncated version of {@code arr} which is guaranteed to be exactly
     * {@code len} elements long. If {@code arr} is already exactly {@code len} elements long, then
     * {@code arr} is returned without copy or modification. If {@code arr} is longer than
     * {@code len}, then a truncated copy is returned. If {@code arr} is shorter than {@code len}
     * then this throws an {@link IllegalArgumentException}.
     */
    public static byte[] truncate(final byte[] arr, final int len) throws IllegalArgumentException {
        if (arr.length == len) {
            return arr;
        } else if (arr.length > len) {
            return Arrays.copyOf(arr, len);
        } else {
            throw new IllegalArgumentException("arr is not at least " + len + " elements long");
        }
    }

    public static SecureRandom getSecureRandom() {
        return LOCAL_RANDOM.get();
    }

    /**
     * Generate the AAD bytes to use when encrypting/decrypting content. The
     * generated AAD is a block of bytes containing the provided message
     * identifier, the string identifier, the sequence number, and the length of
     * the content.
     * 
     * @param messageId
     *            the unique message identifier for the ciphertext.
     * @param idString
     *            the string describing the type of content processed.
     * @param seqNum
     *            the sequence number.
     * @param len
     *            the length of the content.
     * @return
     *         the bytes containing the generated AAD.
     */
    static byte[] generateContentAad(final byte[] messageId, final String idString, final int seqNum, final long len) {
        final byte[] idBytes = idString.getBytes(StandardCharsets.UTF_8);
        final int aadLen = messageId.length + idBytes.length + Integer.SIZE / Byte.SIZE + Long.SIZE / Byte.SIZE;
        final ByteBuffer aad = ByteBuffer.allocate(aadLen);
    
        aad.put(messageId);
        aad.put(idBytes);
        aad.putInt(seqNum);
        aad.putLong(len);
    
        return aad.array();
    }

    static IllegalArgumentException cannotBeNegative(String field) {
        return new IllegalArgumentException(field + " cannot be negative");
    }
}
