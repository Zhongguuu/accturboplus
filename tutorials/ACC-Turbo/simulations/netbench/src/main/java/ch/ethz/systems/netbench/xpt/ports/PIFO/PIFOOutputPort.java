package ch.ethz.systems.netbench.xpt.ports.PIFO;

import ch.ethz.systems.netbench.core.Simulator;
import ch.ethz.systems.netbench.core.log.SimulationLogger;
import ch.ethz.systems.netbench.core.network.*;
import ch.ethz.systems.netbench.ext.basic.IpHeader;
import ch.ethz.systems.netbench.xpt.tcpbase.FullExtTcpPacket;


public class PIFOOutputPort extends OutputPort {


    public PIFOOutputPort(NetworkDevice ownNetworkDevice, NetworkDevice targetNetworkDevice, Link link, long maxQueueSize) {
        super(ownNetworkDevice, targetNetworkDevice, link, new PIFOQueue(maxQueueSize));
    }

    /**
     * Enqueue the given packet.
     * There is no guarantee that the packet is actually sent,
     * as the queue buffer's limit might be reached. If the limit is reached,
     * the packet with lower priority (higher rank) is dropped.
     * @param packet    Packet instance
     */
    @Override
    public void enqueue(Packet packet) {

        // If it is not sending, then the queue is empty at the moment,
        // so this packet can be immediately send
        if (!getIsSending()) {

            // Link is now being utilized
            getLogger().logLinkUtilized(true);

            // Add event when sending is finished
            Simulator.registerEvent(new PacketDispatchedEvent(
                    (long)((double)packet.getSizeBit() / getLink().getBandwidthBitPerNs()),
                    packet,
                    this
            ));

            // It is now sending again
            setIsSending();

            // Log packet for debugging
            if(SimulationLogger.hasPacketsTrackingEnabled()){
                FullExtTcpPacket pk = (FullExtTcpPacket)packet;
                SimulationLogger.logPacket("Time: " + Simulator.getCurrentTime() + " => Packet sent (no queue): SeqNo: " + pk.getSequenceNumber() + ", ACKNo: " + pk.getAcknowledgementNumber() + ", Priority: "+ pk.getPriority());
            }

        } else { // If it is still sending, the packet is added to the queue, making it non-empty

            // Log packet for debugging
            if(SimulationLogger.hasPacketsTrackingEnabled()) {
                FullExtTcpPacket pk = (FullExtTcpPacket)packet;
                SimulationLogger.logPacket("Time: " + Simulator.getCurrentTime() + " => Packet enqueued: SeqNo: " + pk.getSequenceNumber() + ", ACKNo: " + pk.getAcknowledgementNumber() + ", Priority: " + pk.getPriority());
            }

            // Enqueue to the PIFO queue
            PIFOQueue pq = (PIFOQueue) getQueue();
            Packet droppedPacket = (Packet)pq.offerPacket(packet);

            // Increase buffer size to account for the enqueued packet
            increaseBufferOccupiedBits(packet.getSizeBit());
            getLogger().logQueueState(pq.size(), getBufferOccupiedBits());

            if (droppedPacket != null) {

                // Decrease buffer size to account for the dropped packet
                decreaseBufferOccupiedBits(droppedPacket.getSizeBit());
                getLogger().logQueueState(pq.size(), getBufferOccupiedBits());

                // Logging dropped packet
                SimulationLogger.increaseStatisticCounter("PACKETS_DROPPED");
                IpHeader ipHeader = (IpHeader) droppedPacket;
                if (ipHeader.getSourceId() == this.getOwnId()) {
                    SimulationLogger.increaseStatisticCounter("PACKETS_DROPPED_AT_SOURCE");
                }

                if (packet.isTCP()){ //TODO: Add a tag such that is just the ddos logging
                    FullExtTcpPacket fpkt = (FullExtTcpPacket) droppedPacket;
                    // Logging of benign and malicious packets
                    if (fpkt.isURG()) {
                        SimulationLogger.increaseStatisticCounter("MALICIOUS_PACKETS_DROPPED"); // This just does + 1 (since length not added)
                    } else {
                        SimulationLogger.increaseStatisticCounter("BENIGN_PACKETS_DROPPED");
                    }                    
                }
                
            }
        }
    }


}
