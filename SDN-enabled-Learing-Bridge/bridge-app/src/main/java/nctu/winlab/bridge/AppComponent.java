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
package nctu.winlab.bridge;

import com.google.common.collect.ImmutableSet;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Dictionary;
import java.util.Properties;
import static org.onlab.util.Tools.get;

/* Import Libs*/
import com.google.common.collect.Maps; //Provided ConcurrentMap Implementation
import org.onosproject.core.ApplicationId; // Application Identifier
import org.onosproject.core.CoreService;

// Gain Information about existed flow rules & 
// Injecting flow rules into the environment
import org.onosproject.net.flow.FlowRuleService;

// Selector Entries
// import org.onosproject.net.flow.TrafficSelector;    // Abstraction of a slice of network traffic
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;

// Processing packets
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;

// Informations used in API
import org.onlab.packet.Ethernet; // Ethernet Packet
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint; // connect point (including information about )
import org.onosproject.net.DeviceId;    // Representing device identity
import org.onosproject.net.PortNumber; // Represening a port number

// Adding Flow Rule
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;

import java.util.Map; // use on building MacTable


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent{

    // Communicate with the center of controller
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    // Request and emit packets
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    // Apply, Modify Flow Rules
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;


    private final Logger log = LoggerFactory.getLogger(getClass());
    private int IdleTimeOut = 50;
    private int flowRulePriority = 10;
    private ApplicationId appId;
    protected Map<DeviceId, Map<MacAddress, PortNumber>> macTables = Maps.newConcurrentMap();

    /* Proicessor of packets*/
    private LearningBridgeProcessor bridgeProcessor = new LearningBridgeProcessor();

    /** 
        Actions when activate applications in ONOS CLI.
    */
    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.bridge");

        // add processor and Requesting ICMP, ARP packets
        packetService.addProcessor (
            bridgeProcessor, 
            PacketProcessor.director(3) // Priority, high number will be processing first
        );
        requestPackets();

        log.info("Started Learining Bridge.");
    }


    /**
        Actions when deactivated applications in ONOS CLI.
     */
    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId); // remove flow rule by application ID
        packetService.removeProcessor(bridgeProcessor); // remove processor
        log.info("Stopped Learning Bridge.");
    }


    // Select ICMP and ARP packets
    void requestPackets(){
        packetService.requestPackets(
            DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(),
            PacketPriority.REACTIVE, appId);
        packetService.requestPackets(
            DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(),
            PacketPriority.REACTIVE, appId);
    }

    // Learing Bridge Processor
    private class LearningBridgeProcessor implements PacketProcessor {
        @Override
        public void process (PacketContext pc){ // process inbound packets
            if (pc.isHandled()) return; // stop when meeeting handled packets 

            ConnectPoint cp = pc.inPacket().receivedFrom();

            // If the device havent been put in MacTables, add it;
            macTables.putIfAbsent(cp.deviceId(), Maps.newConcurrentMap());

            actLikeSwitch(pc);
        }

        /**
            Floods packet out of all switch ports
            @param pc: PacketContext
         */
        public void actLikeHub(PacketContext pc){
            // from method to get a Traffic treatment and set logical output portnumber
            pc.treatmentBuilder().setOutput(PortNumber.FLOOD); // flood to sent to all ports
            // Trigger the outbound packet to be sent
            pc.send();
        }

        /**
            PACKET_OUT and Record if MAC dst unfoundable
            forwarding packet if MAC dst can be found on MAC table
            @param pc: PacketContext (Passed from activate method)
         */
        public void actLikeSwitch(PacketContext pc){
            // inbound Packet
            InboundPacket inPacket = pc.inPacket();
            Ethernet etherFrame = inPacket.parsed();
            ConnectPoint cp = inPacket.receivedFrom();
            

            // judge Ethertype
            if (etherFrame.getEtherType() != Ethernet.TYPE_IPV4 
                && etherFrame.getEtherType() != Ethernet.TYPE_ARP)
                    return;
            

            // get mactable of current device (via deviceId)
            Map<MacAddress, PortNumber> currentMacTable = macTables.get(cp.deviceId());
            MacAddress src = etherFrame.getSourceMAC(),
                       dst = etherFrame.getDestinationMAC();
            PortNumber outputPort = currentMacTable.get(dst);

            // record source MAC address and PortNumber to Mactable
            currentMacTable.put(src, cp.port());
            log.info("@@@ Add MAC address ==> switch {}, MAC: {}, port: {}  @@@",
                cp.deviceId().toString(), src.toString(), currentMacTable.get(src).toString());


            if (outputPort != null){ // Destination IP address stored on MAC table, install Flow Rule
                // PACKET_OUT
                pc.treatmentBuilder().setOutput(outputPort);
                pc.send();
                log.info("!!!! MAC {} is matched on {}! Install flow rule!  !!!!", dst, outputPort.toString());
                
                // Install flow rule
                FlowRule flowRule = DefaultFlowRule.builder()
                    .withSelector(DefaultTrafficSelector.builder()
                        .matchEthDst(dst)
                        .matchEthSrc(src)
                        .build()
                    )
                    .withTreatment(DefaultTrafficTreatment.builder()
                        .setOutput(outputPort)
                        .build()
                    )
                    .withPriority(flowRulePriority)
                    .withIdleTimeout(IdleTimeOut)
                    .forDevice(cp.deviceId())
                    .fromApp(appId)
                    .build();
                flowRuleService.applyFlowRules(flowRule);
                log.info("!!!! Flow Rule has been installed on {} !!!!", cp.deviceId().toString());
            }
            else { // Destination IP address havent found on MAC table -> Flood out
                actLikeHub(pc);
                log.info("!! MAC {} is missed on {} ! Flood Packet! !!"
                ,dst , cp.deviceId().toString());
            }
        }
    }
}