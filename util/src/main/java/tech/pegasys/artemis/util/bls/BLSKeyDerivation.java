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

import static tech.pegasys.artemis.util.hashToG2.IetfTools.HKDF_Expand;
import static tech.pegasys.artemis.util.hashToG2.IetfTools.HKDF_Extract;
import static tech.pegasys.artemis.util.hashToG2.IetfTools.i2osp;
import static tech.pegasys.artemis.util.hashToG2.IetfTools.os2ip;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.Hash;

/** Implements the BLS key generation defined in EIP-2333 */
public class BLSKeyDerivation {

  // order of the BLS 12-381 curve defined in IETF BLS signature scheme standard
  private static final BigInteger R =
      new BigInteger(
          "52435875175126190479447740508185965837690552500527637822603658699938581184513");

  public static List<Bytes> ikmToLamportSk(final Bytes ikm, final Bytes salt) {
    final Bytes prk = HKDF_Extract(salt, ikm);
    final int l = 8160; // digest size(32) * hash size (255);
    final Bytes okm = HKDF_Expand(prk, Bytes.EMPTY, l);
    final List<Bytes> lamportPk = new ArrayList<>();
    for (int i = 0; i < l; i = i + 32) {
      lamportPk.add(okm.slice(i, 32));
    }
    return lamportPk;
  }

  public static Bytes parentSkToLamportPk(final BigInteger parentSk, BigInteger index) {
    final Bytes salt = Bytes.wrap(i2osp(index, 4));
    final Bytes ikm = Bytes.wrap(i2osp(parentSk, 32));
    final List<Bytes> lamport_0 = ikmToLamportSk(ikm, salt);

    final Bytes not_ikm = flipBits(ikm);
    final List<Bytes> lamport_1 = ikmToLamportSk(Bytes.wrap(not_ikm), salt);

    Bytes lamport_sk = Bytes.EMPTY;
    for (final Bytes b : lamport_0) {
      lamport_sk = Bytes.concatenate(lamport_sk, Hash.sha2_256(b));
    }

    for (final Bytes b : lamport_1) {
      lamport_sk = Bytes.concatenate(lamport_sk, Hash.sha2_256(b));
    }

    return Hash.sha2_256(lamport_sk);
  }

  public static BigInteger hkdfModR(final Bytes ikm) {
    final int l = 48; // L = ceil((1.5 * ceil(log2(r))) / 8) where R = order of the BLS 12-381 curve
    final Bytes prk = HKDF_Extract(Bytes.wrap("BLS-SIG-KEYGEN-SALT-".getBytes()), ikm);
    final Bytes okm = HKDF_Expand(prk, Bytes.EMPTY, l);
    return os2ip(okm).mod(R);
  }

  public static BigInteger deriveChildSk(final BigInteger parentSk, final BigInteger index) {
    final Bytes compressedLamportSk = parentSkToLamportPk(parentSk, index);
    return hkdfModR(compressedLamportSk);
  }

  public static BigInteger deriveMasterSk(final Bytes seed) {
    return hkdfModR(seed);
  }

  public static Bytes flipBits(final Bytes ikm) {
    final byte[] ikmBytes = ikm.toArray();
    final byte[] flipped = new byte[ikmBytes.length];
    for (int i = 0; i < ikmBytes.length; i++) {
      flipped[i] = (byte) ~ikmBytes[i];
    }
    return Bytes.wrap(flipped);
  }
}
