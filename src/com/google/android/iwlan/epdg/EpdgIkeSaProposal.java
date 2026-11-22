/*
 * Copyright 2020 The Android Open Source Project
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

import android.net.ipsec.ike.IkeSaProposal;
import android.support.annotation.Nullable;
import android.util.Log;
import android.util.Pair;

import java.util.LinkedHashSet;
import java.util.Set;

public class EpdgIkeSaProposal extends EpdgSaProposal {
    private static final String TAG = EpdgIkeSaProposal.class.getSimpleName();

    protected final LinkedHashSet<Integer> mProposedPrfAlgos = new LinkedHashSet<>();

    /** IKE SA algorithms only need to be supported by the IKE library itself. */
    @Override
    protected Set<Integer> getPlatformSupportedEncryptionAlgos() {
        return IkeSaProposal.getSupportedEncryptionAlgorithms();
    }

    @Override
    protected Set<Integer> getPlatformSupportedIntegrityAlgos() {
        return IkeSaProposal.getSupportedIntegrityAlgorithms();
    }

    /**
     * Add proposed PRF algorithms by the carrier.
     *
     * @param prfAlgos proposed PRF algorithms
     */
    public void addProposedPrfAlgorithm(int[] prfAlgos) {
        for (int prfAlgo : prfAlgos) {
            if (validateConfig(prfAlgo, VALID_PRF_ALGOS, CONFIG_TYPE_PRF_ALGO)) {
                mProposedPrfAlgos.add(prfAlgo);
            }
        }
    }

    private int[] getPrfAlgos() {
        if (isSaferProposalsPrioritized()) {
            return mProposedPrfAlgos.stream()
                    .sorted(
                            (item1, item2) ->
                                    compareTransformPriority(VALID_PRF_ALGOS, item1, item2))
                    .mapToInt(Integer::intValue)
                    .toArray();
        }

        return mProposedPrfAlgos.stream().mapToInt(Integer::intValue).toArray();
    }

    private int[] getSupportedPrfAlgos() {
        return VALID_PRF_ALGOS.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Builds {@link IkeSaProposal} of carrier proposed encryption algorithms (non-AEAD) cipher
     * suit. Algorithms the device does not support are left out.
     *
     * @return the proposal, or null if a transform type it needs would be empty
     */
    @Nullable
    public IkeSaProposal buildProposedIkeSaProposal() {
        return buildProposal(false, true);
    }

    /**
     * Builds {@link IkeSaProposal} of carrier proposed AEAD algorithms cipher suit. Algorithms the
     * device does not support are left out.
     *
     * @return the proposal, or null if a transform type it needs would be empty
     */
    @Nullable
    public IkeSaProposal buildProposedIkeSaAeadProposal() {
        return buildProposal(true, true);
    }

    /**
     * Builds {@link IkeSaProposal} of Iwlan supported encryption algorithms (non-AEAD) cipher suit.
     * Algorithms the device does not support are left out.
     *
     * @return the proposal, or null if a transform type it needs would be empty
     */
    @Nullable
    public IkeSaProposal buildSupportedIkeSaProposal() {
        return buildProposal(false, false);
    }

    /**
     * Builds {@link IkeSaProposal} of Iwlan supported AEAD algorithms cipher suit. Algorithms the
     * device does not support are left out.
     *
     * @return the proposal, or null if a transform type it needs would be empty
     */
    @Nullable
    public IkeSaProposal buildSupportedIkeSaAeadProposal() {
        return buildProposal(true, false);
    }

    @Nullable
    private IkeSaProposal buildProposal(boolean isAead, boolean isProposed) {
        int[] dhGroups =
                filterSupportedDhGroups((isProposed) ? getDhGroups() : getSupportedDhGroups());

        Pair<Integer, Integer>[] encrAlgos;

        if (isAead) {
            encrAlgos = (isProposed) ? getAeadAlgos() : getSupportedAeadAlgos();
        } else {
            encrAlgos = (isProposed) ? getEncryptionAlgos() : getSupportedEncryptionAlgos();
        }
        encrAlgos = filterSupportedEncryptionAlgos(encrAlgos, isAead);

        int[] integrityAlgos = new int[0];
        if (!isAead) {
            integrityAlgos =
                    filterSupportedIntegrityAlgos(
                            (isProposed) ? getIntegrityAlgos() : getSupportedIntegrityAlgos());
        }

        int[] prfAlgos =
                filterSupported(
                        (isProposed) ? getPrfAlgos() : getSupportedPrfAlgos(),
                        IkeSaProposal.getSupportedPseudorandomFunctions(),
                        CONFIG_TYPE_PRF_ALGO);

        // An IKE SA proposal needs a transform of each type, integrity unless it is AEAD.
        String missingTransform = null;
        if (dhGroups.length == 0) {
            missingTransform = "DH group";
        } else if (encrAlgos.length == 0) {
            missingTransform = "encryption algorithm";
        } else if (!isAead && integrityAlgos.length == 0) {
            missingTransform = "integrity algorithm";
        } else if (prfAlgos.length == 0) {
            missingTransform = "PRF";
        }
        if (missingTransform != null) {
            Log.w(
                    TAG,
                    "Not proposing the "
                            + describeProposal(isAead, isProposed)
                            + " IKE SA proposal: no supported "
                            + missingTransform);
            return null;
        }

        IkeSaProposal.Builder saProposalBuilder = new IkeSaProposal.Builder();
        try {
            for (int dhGroup : dhGroups) {
                saProposalBuilder.addDhGroup(dhGroup);
            }

            for (Pair<Integer, Integer> encrAlgo : encrAlgos) {
                saProposalBuilder.addEncryptionAlgorithm(encrAlgo.first, encrAlgo.second);
            }

            for (int integrityAlgo : integrityAlgos) {
                saProposalBuilder.addIntegrityAlgorithm(integrityAlgo);
            }

            for (int prfAlgo : prfAlgos) {
                saProposalBuilder.addPseudorandomFunction(prfAlgo);
            }

            return saProposalBuilder.build();
        } catch (IllegalArgumentException e) {
            Log.e(
                    TAG,
                    "Not proposing the invalid "
                            + describeProposal(isAead, isProposed)
                            + " IKE SA proposal",
                    e);
            return null;
        }
    }
}
