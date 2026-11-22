/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.google.android.iwlan;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class IwlanHelperMaskTest {
    // A test IMSI (MCC 001, MNC 01), not a real subscriber.
    private static final String NAI = "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org";

    @Test
    public void testMaskNaiForLog_permanentNai_keepsRealmAndLastTwoDigits() {
        assertEquals(
                "***89@nai.epc.mnc001.mcc001.3gppnetwork.org", IwlanHelper.maskNaiForLog(NAI));
    }

    @Test
    public void testMaskNaiForLog_userPartWithoutDigitsAtTheEnd() {
        assertEquals("***@realm.example", IwlanHelper.maskNaiForLog("pseudonym@realm.example"));
        assertEquals("***7@realm.example", IwlanHelper.maskNaiForLog("x7@realm.example"));
    }

    @Test
    public void testMaskNaiForLog_noRealmOrNull() {
        assertEquals("***89", IwlanHelper.maskNaiForLog("0001010123456789"));
        assertEquals("***", IwlanHelper.maskNaiForLog(""));
        assertEquals("null", IwlanHelper.maskNaiForLog(null));
    }
}
