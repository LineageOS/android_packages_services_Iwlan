/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.iwlan.epdg;

import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;

import android.net.ipsec.ike.ChildSaProposal;
import android.net.ipsec.ike.IkeSaProposal;
import android.net.ipsec.ike.SaProposal;
import android.util.Pair;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.MockitoSession;
import org.mockito.quality.Strictness;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RunWith(JUnit4.class)
public class EpdgSaProposalTest {
    // Every encryption and integrity algorithm Iwlan can propose.
    private static final Set<Integer> ALL_ENCRYPTION_ALGOS =
            Set.of(
                    SaProposal.ENCRYPTION_ALGORITHM_AES_CBC,
                    SaProposal.ENCRYPTION_ALGORITHM_AES_CTR,
                    SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8,
                    SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12,
                    SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16);
    private static final Set<Integer> ALL_INTEGRITY_ALGOS =
            Set.of(
                    SaProposal.INTEGRITY_ALGORITHM_NONE,
                    SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96,
                    SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96,
                    SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128,
                    SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192,
                    SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256);

    // The order in which Iwlan proposes its supported transforms.
    private static final int[] SUPPORTED_ENCRYPTION_ALGOS = {
        SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.ENCRYPTION_ALGORITHM_AES_CTR,
    };
    private static final int[] SUPPORTED_AEAD_ALGOS = {
        SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16,
        SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_12,
        SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_8,
    };
    private static final int[] SUPPORTED_KEY_LENGTHS = {
        SaProposal.KEY_LEN_AES_256, SaProposal.KEY_LEN_AES_192, SaProposal.KEY_LEN_AES_128,
    };
    private static final int[] SUPPORTED_INTEGRITY_ALGOS = {
        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256,
        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192,
        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128,
        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96,
        SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96,
    };
    private static final int[] SUPPORTED_DH_GROUPS = {
        SaProposal.DH_GROUP_4096_BIT_MODP,
        SaProposal.DH_GROUP_3072_BIT_MODP,
        SaProposal.DH_GROUP_2048_BIT_MODP,
        SaProposal.DH_GROUP_1536_BIT_MODP,
        SaProposal.DH_GROUP_1024_BIT_MODP,
    };
    private static final int[] SUPPORTED_PRF_ALGOS = {
        SaProposal.PSEUDORANDOM_FUNCTION_SHA2_512,
        SaProposal.PSEUDORANDOM_FUNCTION_SHA2_384,
        SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256,
        SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1,
        SaProposal.PSEUDORANDOM_FUNCTION_AES128_XCBC,
    };

    private MockitoSession mMockitoSession;

    @Before
    public void setUp() throws Exception {
        // The Child SA algorithms a device supports come from IpSecAlgorithm and the device
        // config, so fake them. ChildSaProposal.Builder checks against the same faked set.
        mMockitoSession =
                mockitoSession()
                        .spyStatic(ChildSaProposal.class)
                        .spyStatic(IkeSaProposal.class)
                        .strictness(Strictness.LENIENT)
                        .startMocking();
        setChildSaSupportedAlgorithms(ALL_ENCRYPTION_ALGOS, ALL_INTEGRITY_ALGOS);
    }

    @After
    public void cleanUp() throws Exception {
        mMockitoSession.finishMocking();
    }

    private static void setChildSaSupportedAlgorithms(
            Set<Integer> encryptionAlgos, Set<Integer> integrityAlgos) {
        when(ChildSaProposal.getSupportedEncryptionAlgorithms()).thenReturn(encryptionAlgos);
        when(ChildSaProposal.getSupportedIntegrityAlgorithms()).thenReturn(integrityAlgos);
    }

    private static Set<Integer> without(Set<Integer> algos, int algo) {
        Set<Integer> result = new HashSet<>(algos);
        result.remove(algo);
        return result;
    }

    @Test
    public void testUnsupportedChildSaIntegrityAlgorithmIsDropped() throws Exception {
        setChildSaSupportedAlgorithms(
                ALL_ENCRYPTION_ALGOS,
                without(ALL_INTEGRITY_ALGOS, SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96));
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        epdgChildSaProposal.addProposedEncryptionAlgorithm(
                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, new int[] {SaProposal.KEY_LEN_AES_128});
        epdgChildSaProposal.addProposedIntegrityAlgorithm(
                new int[] {
                    SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96,
                    SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128
                });

        ChildSaProposal proposedProposal = epdgChildSaProposal.buildProposedChildSaProposal();
        ChildSaProposal supportedProposal = epdgChildSaProposal.buildSupportedChildSaProposal();

        assertNotNull(proposedProposal);
        assertEquals(
                List.of(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128),
                proposedProposal.getIntegrityAlgorithms());
        assertNotNull(supportedProposal);
        assertEquals(
                List.of(
                        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256,
                        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192,
                        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128,
                        SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96),
                supportedProposal.getIntegrityAlgorithms());
    }

    @Test
    public void testUnsupportedChildSaEncryptionAlgorithmIsDropped() throws Exception {
        setChildSaSupportedAlgorithms(
                without(ALL_ENCRYPTION_ALGOS, SaProposal.ENCRYPTION_ALGORITHM_AES_CTR),
                ALL_INTEGRITY_ALGOS);
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        epdgChildSaProposal.addProposedEncryptionAlgorithm(
                SaProposal.ENCRYPTION_ALGORITHM_AES_CTR, new int[] {SaProposal.KEY_LEN_AES_256});
        epdgChildSaProposal.addProposedEncryptionAlgorithm(
                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, new int[] {SaProposal.KEY_LEN_AES_256});
        epdgChildSaProposal.addProposedIntegrityAlgorithm(
                new int[] {SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128});

        ChildSaProposal proposedProposal = epdgChildSaProposal.buildProposedChildSaProposal();
        ChildSaProposal supportedProposal = epdgChildSaProposal.buildSupportedChildSaProposal();

        assertNotNull(proposedProposal);
        assertEquals(
                List.of(
                        new Pair<>(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC,
                                SaProposal.KEY_LEN_AES_256)),
                proposedProposal.getEncryptionAlgorithms());
        assertNotNull(supportedProposal);
        assertEquals(
                List.of(
                        new Pair<>(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC,
                                SaProposal.KEY_LEN_AES_256),
                        new Pair<>(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC,
                                SaProposal.KEY_LEN_AES_192),
                        new Pair<>(
                                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC,
                                SaProposal.KEY_LEN_AES_128)),
                supportedProposal.getEncryptionAlgorithms());
    }

    @Test
    public void testProposalsUnchangedWhenAllAlgorithmsSupported() throws Exception {
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        EpdgIkeSaProposal epdgIkeSaProposal = new EpdgIkeSaProposal();

        // What Iwlan proposed before it checked for device support.
        ChildSaProposal.Builder childBuilder = new ChildSaProposal.Builder();
        ChildSaProposal.Builder childAeadBuilder = new ChildSaProposal.Builder();
        IkeSaProposal.Builder ikeBuilder = new IkeSaProposal.Builder();
        IkeSaProposal.Builder ikeAeadBuilder = new IkeSaProposal.Builder();
        for (int dhGroup : SUPPORTED_DH_GROUPS) {
            ikeBuilder.addDhGroup(dhGroup);
            ikeAeadBuilder.addDhGroup(dhGroup);
        }
        for (int algo : SUPPORTED_ENCRYPTION_ALGOS) {
            for (int keyLen : SUPPORTED_KEY_LENGTHS) {
                childBuilder.addEncryptionAlgorithm(algo, keyLen);
                ikeBuilder.addEncryptionAlgorithm(algo, keyLen);
            }
        }
        for (int algo : SUPPORTED_AEAD_ALGOS) {
            for (int keyLen : SUPPORTED_KEY_LENGTHS) {
                childAeadBuilder.addEncryptionAlgorithm(algo, keyLen);
                ikeAeadBuilder.addEncryptionAlgorithm(algo, keyLen);
            }
        }
        for (int algo : SUPPORTED_INTEGRITY_ALGOS) {
            childBuilder.addIntegrityAlgorithm(algo);
            ikeBuilder.addIntegrityAlgorithm(algo);
        }
        for (int algo : SUPPORTED_PRF_ALGOS) {
            ikeBuilder.addPseudorandomFunction(algo);
            ikeAeadBuilder.addPseudorandomFunction(algo);
        }

        assertEquals(childBuilder.build(), epdgChildSaProposal.buildSupportedChildSaProposal());
        assertEquals(
                childAeadBuilder.build(), epdgChildSaProposal.buildSupportedChildSaAeadProposal());
        assertEquals(ikeBuilder.build(), epdgIkeSaProposal.buildSupportedIkeSaProposal());
        assertEquals(ikeAeadBuilder.build(), epdgIkeSaProposal.buildSupportedIkeSaAeadProposal());
    }

    @Test
    public void testConfiguredProposalsUnchangedWhenAllAlgorithmsSupported() throws Exception {
        int[] keyLens = {SaProposal.KEY_LEN_AES_128, SaProposal.KEY_LEN_AES_256};
        int[] integrityAlgos = {
            SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96,
            SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96,
            SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128,
        };
        int[] dhGroups = {SaProposal.DH_GROUP_1024_BIT_MODP, SaProposal.DH_GROUP_2048_BIT_MODP};
        int[] prfAlgos = {
            SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1, SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256,
        };
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        EpdgIkeSaProposal epdgIkeSaProposal = new EpdgIkeSaProposal();
        epdgChildSaProposal.addProposedDhGroups(dhGroups);
        epdgChildSaProposal.enableAddChildSessionRekeyKePayload();
        epdgIkeSaProposal.addProposedDhGroups(dhGroups);
        for (int algo : SUPPORTED_ENCRYPTION_ALGOS) {
            epdgChildSaProposal.addProposedEncryptionAlgorithm(algo, keyLens);
            epdgIkeSaProposal.addProposedEncryptionAlgorithm(algo, keyLens);
        }
        epdgChildSaProposal.addProposedIntegrityAlgorithm(integrityAlgos);
        epdgIkeSaProposal.addProposedIntegrityAlgorithm(integrityAlgos);
        epdgIkeSaProposal.addProposedPrfAlgorithm(prfAlgos);

        ChildSaProposal.Builder childBuilder = new ChildSaProposal.Builder();
        IkeSaProposal.Builder ikeBuilder = new IkeSaProposal.Builder();
        for (int dhGroup : dhGroups) {
            childBuilder.addDhGroup(dhGroup);
            ikeBuilder.addDhGroup(dhGroup);
        }
        for (int algo : SUPPORTED_ENCRYPTION_ALGOS) {
            for (int keyLen : keyLens) {
                childBuilder.addEncryptionAlgorithm(algo, keyLen);
                ikeBuilder.addEncryptionAlgorithm(algo, keyLen);
            }
        }
        for (int algo : integrityAlgos) {
            childBuilder.addIntegrityAlgorithm(algo);
            ikeBuilder.addIntegrityAlgorithm(algo);
        }
        for (int algo : prfAlgos) {
            ikeBuilder.addPseudorandomFunction(algo);
        }

        assertEquals(childBuilder.build(), epdgChildSaProposal.buildProposedChildSaProposal());
        assertEquals(ikeBuilder.build(), epdgIkeSaProposal.buildProposedIkeSaProposal());
    }

    @Test
    public void testChildSaProposalWithoutSupportedIntegrityIsSkipped() throws Exception {
        setChildSaSupportedAlgorithms(
                ALL_ENCRYPTION_ALGOS, Set.of(SaProposal.INTEGRITY_ALGORITHM_NONE));
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        epdgChildSaProposal.addProposedEncryptionAlgorithm(
                SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, new int[] {SaProposal.KEY_LEN_AES_128});
        epdgChildSaProposal.addProposedIntegrityAlgorithm(
                new int[] {SaProposal.INTEGRITY_ALGORITHM_AES_XCBC_96});

        // Without any integrity algorithm left, the non-AEAD proposals are skipped instead of
        // being proposed without integrity protection.
        assertNull(epdgChildSaProposal.buildProposedChildSaProposal());
        assertNull(epdgChildSaProposal.buildSupportedChildSaProposal());
        // AEAD proposals need no integrity algorithm.
        assertNotNull(epdgChildSaProposal.buildSupportedChildSaAeadProposal());
    }

    @Test
    public void testChildSaProposalWithoutSupportedEncryptionIsSkipped() throws Exception {
        setChildSaSupportedAlgorithms(
                Set.of(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC), ALL_INTEGRITY_ALGOS);
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        epdgChildSaProposal.addProposedAeadAlgorithm(
                SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16, new int[] {SaProposal.KEY_LEN_AES_256});

        assertNull(epdgChildSaProposal.buildProposedChildSaAeadProposal());
        assertNull(epdgChildSaProposal.buildSupportedChildSaAeadProposal());
        assertNotNull(epdgChildSaProposal.buildSupportedChildSaProposal());
    }

    @Test
    public void testIkeSaProposalWithoutSupportedIntegrityIsSkipped() throws Exception {
        when(IkeSaProposal.getSupportedIntegrityAlgorithms())
                .thenReturn(Set.of(SaProposal.INTEGRITY_ALGORITHM_NONE));
        EpdgIkeSaProposal epdgIkeSaProposal = new EpdgIkeSaProposal();

        assertNull(epdgIkeSaProposal.buildSupportedIkeSaProposal());
        assertNotNull(epdgIkeSaProposal.buildSupportedIkeSaAeadProposal());
    }

    @Test
    public void testEmptyConfiguredProposalIsSkipped() throws Exception {
        EpdgChildSaProposal epdgChildSaProposal = new EpdgChildSaProposal();
        EpdgIkeSaProposal epdgIkeSaProposal = new EpdgIkeSaProposal();

        // Nothing configured: the IKE library would reject these proposals.
        assertNull(epdgChildSaProposal.buildProposedChildSaProposal());
        assertNull(epdgChildSaProposal.buildProposedChildSaAeadProposal());
        assertNull(epdgIkeSaProposal.buildProposedIkeSaProposal());
        assertNull(epdgIkeSaProposal.buildProposedIkeSaAeadProposal());
    }
}
