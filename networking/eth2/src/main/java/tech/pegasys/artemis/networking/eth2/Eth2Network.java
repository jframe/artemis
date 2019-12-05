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

package tech.pegasys.artemis.networking.eth2;

import java.util.Optional;
import java.util.stream.Stream;
import tech.pegasys.artemis.networking.eth2.peers.Eth2Peer;
import tech.pegasys.artemis.networking.eth2.peers.Eth2PeerManager;
import tech.pegasys.artemis.networking.p2p.network.DelegatingP2PNetwork;
import tech.pegasys.artemis.networking.p2p.network.P2PNetwork;
import tech.pegasys.artemis.networking.p2p.peer.NodeId;

public class Eth2Network extends DelegatingP2PNetwork implements P2PNetwork {
  private final Eth2PeerManager peerManager;

  public Eth2Network(final P2PNetwork network, final Eth2PeerManager peerManager) {
    super(network);
    this.peerManager = peerManager;
  }

  @Override
  public Optional<Eth2Peer> getPeer(final NodeId id) {
    return peerManager.getPeer(id);
  }

  @Override
  public Stream<Eth2Peer> streamPeers() {
    return peerManager.streamPeers();
  }

  @Override
  public long getPeerCount() {
    // TODO - look into keep separate collections for pending peers / validated peers so
    // we don't have to iterate over the peer list to get this count.
    return streamPeers().count();
  }
}