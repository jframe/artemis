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

package tech.pegasys.artemis.beaconrestapi.beaconhandlers;

import static tech.pegasys.artemis.datastructures.util.BeaconStateUtil.compute_start_slot_at_epoch;

import com.google.common.primitives.UnsignedLong;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.artemis.beaconrestapi.handlerinterfaces.BeaconRestApiHandler;
import tech.pegasys.artemis.datastructures.blocks.BeaconBlock;
import tech.pegasys.artemis.storage.ChainStorageClient;

public class BeaconBlockHandler implements BeaconRestApiHandler {

  private final ChainStorageClient client;

  public BeaconBlockHandler(ChainStorageClient client) {
    this.client = client;
  }

  @Override
  public String getPath() {
    return "/beacon/block/";
  }

  @Override
  public Object handleRequest(RequestParams param) {
    Map<String, List<String>> queryParamMap = param.getQueryParamMap();
    Map<String, Object> jsonObject = new HashMap<>();
    BeaconBlock block;
    Bytes32 blockRoot;
    if (queryParamMap.containsKey("root")) {
      Bytes32 root = Bytes32.fromHexString(param.getQueryParam("root"));
      return client.getStore() != null ? client.getStore().getBlock(root) : null;
    } else if (queryParamMap.containsKey("epoch")) {
      UnsignedLong epoch = UnsignedLong.valueOf(param.getQueryParam("epoch"));
      Optional<Bytes32> blockRootAtSlot =
          client.getBlockRootBySlot(compute_start_slot_at_epoch(epoch));
      blockRoot = blockRootAtSlot.orElse(null);
      block =
          client.getStore() != null && blockRootAtSlot.isPresent()
              ? client.getStore().getBlock(blockRootAtSlot.get())
              : null;
    } else if (queryParamMap.containsKey("slot")) {
      UnsignedLong slot = UnsignedLong.valueOf(param.getQueryParam("slot"));
      Optional<Bytes32> blockRootAtSlot = client.getBlockRootBySlot(slot);
      blockRoot = blockRootAtSlot.orElse(null);
      block =
          client.getStore() != null && blockRootAtSlot.isPresent()
              ? client.getStore().getBlock(blockRootAtSlot.get())
              : null;
    } else {
      return null;
    }
    jsonObject.put("block", block);
    jsonObject.put("blockRoot", blockRoot.toHexString());
    return jsonObject;
  }
}
