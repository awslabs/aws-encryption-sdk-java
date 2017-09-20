package com.amazonaws.encryptionsdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import com.amazonaws.encryptionsdk.internal.Utils;

public class UtilsTest {
    @Test
    public void compareObjectIdentityTest() throws Exception {
        assertNotEquals(0, Utils.compareObjectIdentity(null, new Object()));
        assertNotEquals(0, Utils.compareObjectIdentity(new Object(), null));

        assertEquals(0, Utils.compareObjectIdentity(Utils.class, Utils.class));
        assertNotEquals(0, Utils.compareObjectIdentity(new Object(), new Object()));
    }

    @Test
    public void compareObjectIdentity_handlesHashCodeCollisions() {
        // With this large of an array, it is overwhelmingly likely that we will see two objects with identical
        // identity hash codes.
        Object[] testArray = new Object[512_000];

        for (int i = 0; i < testArray.length; i++) {
            testArray[i] = new Object();
        }

        Arrays.sort(testArray, Utils::compareObjectIdentity);

        // Verify that we do not have any objects that are equal (compare to zero) in the array.
        // We know the primary sort is by hashcode, so we'll just do exhaustive comparison within each hashcode.

        boolean sawCollison = false;
        for (int i = 0; i <testArray.length; i++) {
            int hashCode = System.identityHashCode(testArray[i]);

            int endOfHashGroup = i;
            while (endOfHashGroup + 1 < testArray.length
                    && System.identityHashCode(testArray[endOfHashGroup + 1]) == hashCode) {
                endOfHashGroup++;
            }

            if (i != endOfHashGroup) {
                sawCollison = true;
            }

            for (int a = i; a <= endOfHashGroup; a++) {
                for (int b = a + 1; b <= endOfHashGroup; b++) {
                    if (a != b) {
                        assertNotEquals(0, Utils.compareObjectIdentity(a, b));
                    }
                }
            }
        }

        assertTrue(sawCollison);
    }

    @Test
    public void testSaturatingAdd() throws Exception {
        assertEquals(0, Utils.saturatingAdd(0, 0));
        assertEquals(2, Utils.saturatingAdd(1, 1));
        assertEquals(-2, Utils.saturatingAdd(-1, -1));
        assertEquals(0, Utils.saturatingAdd(-1, +1));
        assertEquals(0, Utils.saturatingAdd(+1, -1));

        assertEquals(Long.MIN_VALUE, Utils.saturatingAdd(Long.MIN_VALUE + 1, -2));
        assertEquals(Long.MAX_VALUE, Utils.saturatingAdd(Long.MAX_VALUE - 1, +2));
        assertEquals(Long.MAX_VALUE, Utils.saturatingAdd(Long.MAX_VALUE, Long.MAX_VALUE));
        assertEquals(Long.MIN_VALUE, Utils.saturatingAdd(Long.MIN_VALUE, Long.MIN_VALUE));
    }
}

