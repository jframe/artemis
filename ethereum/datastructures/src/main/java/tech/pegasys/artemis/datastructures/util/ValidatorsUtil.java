/*
 * Copyright 2019 ConsenSys AG.
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

package tech.pegasys.artemis.datastructures.util;

import com.google.common.primitives.UnsignedLong;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import tech.pegasys.artemis.datastructures.state.BeaconState;
import tech.pegasys.artemis.datastructures.state.BeaconStateWithCache;
import tech.pegasys.artemis.datastructures.state.Validator;
import tech.pegasys.artemis.util.config.Constants;

public class ValidatorsUtil {

  /**
   * Check if (this) validator is active in the given epoch.
   *
   * @param epoch - The epoch under consideration.
   * @return A boolean indicating if the validator is active.
   * @see <a>
   *     https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#is_active_validator
   *     </a>
   */
  public static boolean is_active_validator(Validator validator, UnsignedLong epoch) {
    return validator.getActivation_epoch().compareTo(epoch) <= 0
        && epoch.compareTo(validator.getExit_epoch()) < 0;
  }

  /**
   * Check if validator is eligible to be placed into the activation queue.
   *
   * @param validator the validator
   * @return true if eligible for the activation queue otherwise false
   */
  public static boolean is_eligible_for_activation_queue(Validator validator) {
    return validator.getActivation_eligibility_epoch().equals(Constants.FAR_FUTURE_EPOCH)
        && validator
            .getEffective_balance()
            .equals(UnsignedLong.valueOf(Constants.MAX_EFFECTIVE_BALANCE));
  }

  /**
   * Check if validator is eligible for activation.
   *
   * @param state the beacon state
   * @param validator the validator
   * @return true if the validator is eligible for activation
   */
  public static boolean is_eligible_for_activation(BeaconState state, Validator validator) {
    return validator
                .getActivation_eligibility_epoch()
                .compareTo(state.getFinalized_checkpoint().getEpoch())
            <= 0
        && validator.getActivation_epoch().equals(Constants.FAR_FUTURE_EPOCH);
  }

  /**
   * Get active validator indices at ``epoch``.
   *
   * @param state - Current BeaconState
   * @param epoch - The epoch under consideration.
   * @return A list of indices representing the active validators for the given epoch.
   * @see
   *     <a>https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#get_active_validator_indices</a>
   */
  public static List<Integer> get_active_validator_indices(BeaconState state, UnsignedLong epoch) {
    return BeaconStateWithCache.getTransitionCaches(state)
        .getActiveValidators()
        .get(
            epoch,
            e -> {
              List<Validator> validators = state.getValidators();
              return IntStream.range(0, validators.size())
                  .filter(index -> is_active_validator(validators.get(index), epoch))
                  .boxed()
                  .collect(Collectors.toList());
            });
  }

  /**
   * Decrease validator balance by ``delta`` with underflow protection.
   *
   * @param state
   * @param index
   * @param delta
   * @see
   *     <a>https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#decrease_balance</a>
   */
  public static void decrease_balance(BeaconState state, int index, UnsignedLong delta) {
    UnsignedLong newBalance =
        delta.compareTo(state.getBalances().get(index)) > 0
            ? UnsignedLong.ZERO
            : state.getBalances().get(index).minus(delta);
    state.getBalances().set(index, newBalance);
  }

  /**
   * Increase validator balance by ``delta``.
   *
   * @param state
   * @param index
   * @param delta
   * @see
   *     <a>https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#increase_balance</a>
   */
  public static void increase_balance(BeaconState state, int index, UnsignedLong delta) {
    state.getBalances().set(index, state.getBalances().get(index).plus(delta));
  }

  /**
   * Determines if a validator has a balance that can be slashed
   *
   * @param validator
   * @param epoch
   * @return
   * @see
   *     <a>https://github.com/ethereum/eth2.0-specs/blob/v0.8.0/specs/core/0_beacon-chain.md#is_slashable_validator<a/>
   */
  public static boolean is_slashable_validator(Validator validator, UnsignedLong epoch) {
    return !validator.isSlashed()
        && (validator.getActivation_epoch().compareTo(epoch) <= 0
            && epoch.compareTo(validator.getWithdrawable_epoch()) < 0);
  }
}
