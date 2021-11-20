/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


// Gain Information about existed flow rules & 
// Injecting flow rules into the environment
import org.onosproject.net.host.HostService; // host service
import org.onosproject.net.edge.EdgePortService; // Edge port Service
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

// Selector Entries
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;

// Processing packets
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;

// Informations used in API
import org.onlab.packet.Ethernet; // Ethernet Packet
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.ConnectPoint; // connect point (including information about )
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;    // Representing device identity
import org.onosproject.net.PortNumber; // Represening a port number
import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;


import com.google.common.collect.Maps;
import java.util.Map; // use on building MacTable
import java.util.Optional; // use to specify if it is nullable
import java.util.Set;

import javax.crypto.Mac;

import java.nio.ByteBuffer;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private Map< Ip4Address, MacAddress > recordMAC = Maps.newConcurrentMap();
    private Map< MacAddress, ConnectPoint > recordCp = Maps.newConcurrentMap();
    private ProxyArpProcessor proxyArpProcessor = new ProxyArpProcessor();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;
  
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        
        packetService.addProcessor (
            proxyArpProcessor, 
            PacketProcessor.director(3) // Priority, high number will be processing first
        );
        requestPackets();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(proxyArpProcessor);
        log.info("Stopped");
    }

    /**
     * Request ARP packet
     */
    private void requestPackets(){
        packetService.requestPackets(
            DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build(),
            PacketPriority.REACTIVE, appId);
    }

    /**
     * Processor
     *  1. ARP request: 
     *      Analyze requested ARP packet, and emited to all Edge Point
     *  2. ARP reply:
     *      Accept replied ARP packet and record to map
     */
    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process (PacketContext pc){ // process inbound packets
            if (pc.isHandled()) // stop when meeeting handled packets 
                return; 
            if (pc.inPacket().parsed().getEtherType() != Ethernet.TYPE_ARP)
                return;

            ARP arpPacket = (ARP) pc.inPacket().parsed().getPayload();
            // Recording IP to MAC, MAC to CP (for packet out in ARP_reply)
            recordMAC.putIfAbsent( Ip4Address.valueOf(
                arpPacket.getSenderProtocolAddress()),
                pc.inPacket().parsed().getSourceMAC()
            );
            recordCp.putIfAbsent( 
                pc.inPacket().parsed().getSourceMAC(), 
                pc.inPacket().receivedFrom() 
            );


            // Judge Op code to do
            if (arpPacket.getOpCode() == ARP.OP_REQUEST){
                // log.info("Received ARP REQUEST packets");
                arpRequestPkt(pc);
            }
            else if (arpPacket.getOpCode() == ARP.OP_REPLY){
                // log.info("Received ARP REPLY packet.");
                arpReplyPkt(pc);
            }
        }

        // ARP_REQUEST
        private void arpRequestPkt(PacketContext pc){
            ARP arpPacket = (ARP) pc.inPacket().parsed().getPayload();
            Ethernet etherFrame = pc.inPacket().parsed();
            MacAddress targetMAC = recordMAC.get( Ip4Address.valueOf(arpPacket.getTargetProtocolAddress()) );

            // stored previously -> emit arp reply packet
            if (targetMAC != null){
                log.info("TABLE HIT. Requested MAC = {}", targetMAC.toString());
                emitARPpkt(targetMAC, etherFrame.getSourceMAC(),
                    pc.inPacket().receivedFrom(),
                    ARP.OP_REPLY, 
                    arpPacket.getTargetProtocolAddress(), 
                    arpPacket.getSenderProtocolAddress()
                );
            }
            // Packet out to all Edge ports
            else{
                log.info("TABLE MISS. Send request to edge ports");
                for (ConnectPoint cp: edgePortService.getEdgePoints()){
                    // Only packet out to edge port
                    if (! cp.equals(pc.inPacket().receivedFrom())){
                        OutboundPacket outPacket = new DefaultOutboundPacket(
                            cp.deviceId(),
                            DefaultTrafficTreatment.builder().setOutput(cp.port()).build(),
                            ByteBuffer.wrap(pc.inPacket().parsed().serialize())
                        );
                        packetService.emit(outPacket);
                    }
                    // else{
                    //     log.info("Avoid packet out to origin: {}", cp.toString());
                    // }
                }
            }
        }

        // ARP Reply
        private void arpReplyPkt(PacketContext pc){
            ARP arpPacket = (ARP) pc.inPacket().parsed().getPayload();
            ConnectPoint target = recordCp.get( MacAddress.valueOf(arpPacket.getTargetHardwareAddress()) );

            // packet out to target
            if (target != null){
                log.info("RECV REPLY. Requested MAC = {}", MacAddress.valueOf(arpPacket.getSenderHardwareAddress()).toString());

                // add Traffic Treatment and emit
                OutboundPacket outPacket = new DefaultOutboundPacket(
                        target.deviceId(),
                        DefaultTrafficTreatment.builder().setOutput(target.port()).build(),
                        ByteBuffer.wrap(pc.inPacket().parsed().serialize())
                    );
                packetService.emit(outPacket);
            }
        }
    }
    
    /**
     * Create corresponding arp packet and emit to target connect point
     */
    private void emitARPpkt(MacAddress ethSrc, MacAddress ethDst,
        ConnectPoint targetCp,
        short opcode, 
        byte[] senderProtocalAddress,
        byte[] targetProtocalAddress){
        
        // Ethernet Packet
        Ethernet eth = new Ethernet();
        eth.setDestinationMACAddress(ethDst);
        eth.setSourceMACAddress(ethSrc);
        eth.setEtherType(Ethernet.TYPE_ARP);
        
        // ARP payload
        ARP arp = new ARP();
        arp.setOpCode(opcode);
        arp.setProtocolType(ARP.PROTO_TYPE_IP);
        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);

        arp.setProtocolAddressLength((byte) Ip4Address.BYTE_LENGTH);
        arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arp.setSenderHardwareAddress(ethSrc.toBytes());
        arp.setSenderProtocolAddress(senderProtocalAddress);
        arp.setTargetHardwareAddress(ethDst.toBytes());
        arp.setTargetProtocolAddress(targetProtocalAddress);

        eth.setPayload(arp);
        
        // add Traffic Treatment and emit
        OutboundPacket outPacket = new DefaultOutboundPacket(
            targetCp.deviceId(),
            DefaultTrafficTreatment.builder().setOutput(targetCp.port()).build(),
            ByteBuffer.wrap(eth.serialize())
        );
        packetService.emit(outPacket);
    }
}

