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

import android.net.ipsec.ike.ChildSaProposal;
import android.support.annotation.Nullable;
import android.util.Log;
import android.util.Pair;

import java.util.Set;

public class EpdgChildSaProposal extends EpdgSaProposal {
    private static final String TAG = EpdgChildSaProposal.class.getSimpleName();

    private boolean mAddChildSessionRekeyKePayload = false;

    /**
     * Child SA algorithms must be supported by the kernel, i.e. be in {@link
     * android.net.IpSecAlgorithm#getSupportedAlgorithms()}.
     */
    @Override
    protected Set<Integer> getPlatformSupportedEncryptionAlgos() {
        return ChildSaProposal.getSupportedEncryptionAlgorithms();
    }

    @Override
    protected Set<Integer> getPlatformSupportedIntegrityAlgos() {
        return ChildSaProposal.getSupportedIntegrityAlgorithms();
    }

    /**
     * Add DH Groups to child session during rekey with KE payload. IKE library doesn't add KE
     * payload if dh groups are not set in child session params. Use the same groups as that of IKE
     * session.
     */
    public void enableAddChildSessionRekeyKePayload() {
        mAddChildSessionRekeyKePayload = true;
    }

    /**
     * Builds {@link ChildSaProposal} of carrier proposed encryption algorithms (non-AEAD) cipher
     * suit. Algorithms the device does not support are left out.
     *
     * @return the proposal, or null if it would be empty or lose its integrity protection
     */
    @Nullable
    public ChildSaProposal buildProposedChildSaProposal() {
        return buildProposal(false, true);
    }

    /**
     * Builds {@link ChildSaProposal} of carrier proposed AEAD algorithms cipher suit. Algorithms
     * the device does not support are left out.
     *
     * @return the proposal, or null if it would be empty
     */
    @Nullable
    public ChildSaProposal buildProposedChildSaAeadProposal() {
        return buildProposal(true, true);
    }

    /**
     * Builds {@link ChildSaProposal} of Iwlan supported encryption algorithms (non-AEAD) cipher
     * suit. Algorithms the device does not support are left out.
     *
     * @return the proposal, or null if it would be empty or lose its integrity protection
     */
    @Nullable
    public ChildSaProposal buildSupportedChildSaProposal() {
        return buildProposal(false, false);
    }

    /**
     * Builds {@link ChildSaProposal} of Iwlan supported AEAD algorithms cipher suit. Algorithms the
     * device does not support are left out.
     *
     * @return the proposal, or null if it would be empty
     */
    @Nullable
    public ChildSaProposal buildSupportedChildSaAeadProposal() {
        return buildProposal(true, false);
    }

    @Nullable
    private ChildSaProposal buildProposal(boolean isAead, boolean isProposed) {
        Pair<Integer, Integer>[] encrAlgos;

        if (isAead) {
            encrAlgos = (isProposed) ? getAeadAlgos() : getSupportedAeadAlgos();
        } else {
            encrAlgos = (isProposed) ? getEncryptionAlgos() : getSupportedEncryptionAlgos();
        }
        encrAlgos = filterSupportedEncryptionAlgos(encrAlgos, isAead);
        if (encrAlgos.length == 0) {
            Log.w(
                    TAG,
                    "Not proposing the "
                            + describeProposal(isAead, isProposed)
                            + " Child SA proposal: no supported encryption algorithm");
            return null;
        }

        int[] integrityAlgos = new int[0];
        if (!isAead) {
            int[] proposalIntegrityAlgos =
                    (isProposed) ? getIntegrityAlgos() : getSupportedIntegrityAlgos();
            integrityAlgos = filterSupportedIntegrityAlgos(proposalIntegrityAlgos);
            // Never turn a proposal with integrity protection into one without.
            if (proposalIntegrityAlgos.length > 0 && integrityAlgos.length == 0) {
                Log.w(
                        TAG,
                        "Not proposing the "
                                + describeProposal(isAead, isProposed)
                                + " Child SA proposal: no supported integrity algorithm");
                return null;
            }
        }

        ChildSaProposal.Builder saProposalBuilder = new ChildSaProposal.Builder();
        try {
            if (mAddChildSessionRekeyKePayload) {
                int[] dhGroups = filterSupportedDhGroups(getDhGroups());
                for (int dhGroup : dhGroups) {
                    saProposalBuilder.addDhGroup(dhGroup);
                }
            }

            for (Pair<Integer, Integer> encrAlgo : encrAlgos) {
                saProposalBuilder.addEncryptionAlgorithm(encrAlgo.first, encrAlgo.second);
            }

            for (int integrityAlgo : integrityAlgos) {
                saProposalBuilder.addIntegrityAlgorithm(integrityAlgo);
            }

            return saProposalBuilder.build();
        } catch (IllegalArgumentException e) {
            Log.e(
                    TAG,
                    "Not proposing the invalid "
                            + describeProposal(isAead, isProposed)
                            + " Child SA proposal",
                    e);
            return null;
        }
    }
}
