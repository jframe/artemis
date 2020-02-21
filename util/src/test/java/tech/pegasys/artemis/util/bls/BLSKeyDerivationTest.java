/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.artemis.util.bls;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.Resources;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class BLSKeyDerivationTest {

  @ParameterizedTest
  @MethodSource("keyDerivationTestCases")
  void derivesMasterSkFromSeed(final Map<String, String> testCase) {
    final Bytes seed = Bytes.fromHexString(testCase.get("seed"));
    final BigInteger expectedMasterSk = new BigInteger(testCase.get("master_SK"));
    final BigInteger masterSk = BLSKeyDerivation.deriveMasterSk(seed);
    assertThat(masterSk).isEqualTo(expectedMasterSk);
  }

  @ParameterizedTest
  @MethodSource("keyDerivationTestCases")
  void derivesChildSkFromMasterSkAndIndex(final Map<String, String> testCase) {
    final BigInteger masterSk = new BigInteger(testCase.get("master_SK"));
    final BigInteger childIndex = new BigInteger(testCase.get("child_index"));
    final BigInteger expectedChildSk = new BigInteger(testCase.get("child_SK"));
    final BigInteger childSk = BLSKeyDerivation.deriveChildSk(masterSk, childIndex);
    assertThat(childSk).isEqualTo(expectedChildSk);
  }

  @Test
  public void flipBitsRoundTripsToOriginalValue() {
    final Bytes bytes = Bytes.of("somethinghere".getBytes());
    final Bytes flippedBytes = BLSKeyDerivation.flipBits(bytes);
    assertThat(flippedBytes.and(bytes).isZero()).isTrue();

    final Bytes roundTrippedBits = BLSKeyDerivation.flipBits(flippedBytes);
    assertThat(roundTrippedBits).isEqualTo(bytes);
  }

  @SuppressWarnings("UnstableApiUsage")
  private static List<Map<String, String>> keyDerivationTestCases() throws IOException {
    final ObjectMapper objectMapper = new ObjectMapper();
    return objectMapper.readValue(
        Resources.getResource("blsKeyDerivationTestCases/kdf_testcases.json"),
        new TypeReference<>() {});
  }
}
