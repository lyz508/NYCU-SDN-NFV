/*
 * Copyright 2022-present Open Networking Foundation
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
package nctu.winlab.vlanbasedsr;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


// Gain Information about existed flow rules & 
// Injecting flow rules into the environment
import org.onosproject.net.flow.FlowRuleService;

// Selector Entries
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector.Builder;

// Processing packets
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.Link;

// Informations used in API
import org.onlab.packet.Ethernet; // Ethernet Packet
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint; // connect point (including information about )
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;    // Representing device identity
import org.onosproject.net.PortNumber; // Represening a port number
import org.onlab.packet.TpPort; // for port match
import org.onlab.packet.IPv4;
import org.onlab.packet.UDP;
import org.onlab.packet.DHCP;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IpAddress;

// Find Path
import org.onosproject.net.topology.PathService;

// Adding Flow Rule
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.Path;

// FlowObjective Service
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;

import com.google.common.collect.Maps;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;

// Vlan
import org.onlab.packet.VlanId;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent{

    /**Fields */
    private ApplicationId appId;
    private ArrayList<DeviceId> edgeSwitchList = new ArrayList<>();
    private Map<DeviceId, String> edgeSwitchSubnetMap = Maps.newConcurrentMap();
    private Map<DeviceId, String> edgeSwitchIDMap = Maps.newConcurrentMap();
    private Map<DeviceId, String> edgeSwitchPortMap = Maps.newConcurrentMap();
    private Map<DeviceId, IpPrefix> edgeSwitchPrefixMap = Maps.newConcurrentMap();
    private Map<ConnectPoint, MacAddress> cpMacMap = Maps.newConcurrentMap();

    private int vlanPriority = 10;
    private int vlanTimeout = 600;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final NameConfigListener cfgListener = new NameConfigListener();
    private final ConfigFactory<ApplicationId, NameConfig> factory =
        new ConfigFactory<ApplicationId, NameConfig>(
            APP_SUBJECT_FACTORY, NameConfig.class, "VlanBasedSR") {
            @Override
            public NameConfig createConfig() {
            return new NameConfig();
            }
        };


    /**Regist services */
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PathService pathService;

    // Apply, Modify Flow Rules
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.vlanbasedsr");

        // Add netcfgs listener   
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);

        // Ask for pkt
        requestPackets();

        // Append ini flow rule to edge switches
        appendIniFlowRules();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);

        flowRuleService.removeFlowRulesById(appId);

        log.info("Stopped");
    }

    void requestPackets(){
        packetService.requestPackets(
            DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(),
            PacketPriority.REACTIVE, appId);    
    }

    private void appendIniFlowRules(){
        // Append flow rule for each EdgeSwitch
        for (int i=0; i<edgeSwitchList.size(); i++){
            for (int j=0; j<edgeSwitchList.size(); j++){
                if (i != j){
                    String subnets = edgeSwitchSubnetMap.get(edgeSwitchList.get(j)),
                            subnetIP = subnets.split("/")[0],
                            subnetMask = subnets.split("/")[1],
                            edgeSwitchsegID = edgeSwitchIDMap.get(edgeSwitchList.get(j));
                    log.info("ip {}, mask {}", subnetIP, subnetMask);
                    int subnetPrefix = Integer.parseInt(subnetMask);
                    IpAddress ipAddress = IpAddress.valueOf(subnetIP);
                    IpPrefix ipPrefix = IpPrefix.valueOf(ipAddress, subnetPrefix);
                    VlanId dstVlanId = VlanId.vlanId(edgeSwitchsegID);

                    log.info("Add Forwarding Objective on {}, push vlan ID {} via edge switch {}", edgeSwitchList.get(i).toString(), dstVlanId.toString(), edgeSwitchList.get(j).toString());

                    Set<Path> res;
                    res = pathService.getPaths(edgeSwitchList.get(i), edgeSwitchList.get(j));
                    log.info("From Device {} to {}", edgeSwitchList.get(i).toString(), edgeSwitchList.get(j).toString());
                    VlanId targetId = dstVlanId;

                    if ( res.size() > 0 ){
                        log.info("List paths: ");
                        ArrayList<Path> arrlst = new ArrayList<>(res);
                        List<Link> lks = arrlst.get(0).links();
                        
                        // Get links in path and print out
                        if (lks != null){
                            // Print path to log info
                            for (int q=0; q<lks.size(); q++){
                            ConnectPoint from=lks.get(q).src(), 
                                to=lks.get(q).dst();
                            log.info("From {}/{} to {}/{}", 
                                from.deviceId().toString(), from.port().toString(), 
                                to.deviceId().toString(), to.port().toString());
                            }
                            log.info("!!Start to build flow rule to construct the path!!");

                            // Build Flow Rule to construct the path
                            installFlowRule(lks, targetId);

                            // install first flow rule for paths
                            PortNumber outputTarget = lks.get(0).src().port();
                            log.info("Port Number: {}", outputTarget.toString());

                            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                                .withSelector(
                                    DefaultTrafficSelector.builder()
                                    .matchEthType(Ethernet.TYPE_IPV4)
                                    .matchIPDst(ipPrefix)
                                    .build()
                                )
                                .withTreatment(
                                    DefaultTrafficTreatment.builder()
                                    .pushVlan()
                                    .setVlanId(dstVlanId)
                                    .setOutput(outputTarget)
                                    .build()
                                )
                                .withPriority(10)
                                .makeTemporary(6000)
                                .withFlag(ForwardingObjective.Flag.VERSATILE)
                                .fromApp(appId)
                                .add();
                            flowObjectiveService.forward(edgeSwitchList.get(i), forwardingObjective);
                        }
                    }
                    else{
                        return;
                    }
                }
            }
        }

        // install rule for same subnet pkt transmitting
        for (ConnectPoint cpNow: cpMacMap.keySet()){
            // pop Vlan ID and send to the MAC address
            PortNumber targetPortNumber = cpNow.port();
            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).matchEthDst(cpMacMap.get(cpNow));
            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder().setOutput(targetPortNumber);
            ForwardingObjective forwardingObjective = genForwarding(selectorBuilder, treatmentBuilder);
            flowObjectiveService.forward(cpNow.deviceId(), forwardingObjective);
        }

        log.info("Appended ini flow rule");
    }

    // Install flow rule with a Path List
    private void installFlowRule(List<Link> lks, VlanId matchId){
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
        DeviceId des_devid = lks.get(lks.size()-1).dst().deviceId();
        ForwardingObjective forwardingObjective;


        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4).matchVlanId(matchId);

        // Middle 
        for (int i=1; i<lks.size(); i++){
            ConnectPoint now_dev = lks.get(i).src();
            treatmentBuilder = DefaultTrafficTreatment.builder().setOutput(now_dev.port());
            forwardingObjective = genForwarding(selectorBuilder, treatmentBuilder);
            flowObjectiveService.forward(now_dev.deviceId(), forwardingObjective);
            log.info("~~Apply flow rule on {}, output to port {}~~", now_dev.deviceId().toString(), now_dev.port().toString());
        }

        // Final
        log.info("Final, pop VlanID and flood");
        for (ConnectPoint cpNow: cpMacMap.keySet()){
            // pop Vlan ID and send to the MAC address
            if (cpNow.deviceId().equals(des_devid)){
                //log.info("For destination cp: {}", cpNow.toString());
                PortNumber targetPortNumber = cpNow.port();
                selectorBuilder = DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).matchEthDst(cpMacMap.get(cpNow)).matchVlanId(matchId);
                treatmentBuilder = DefaultTrafficTreatment.builder().popVlan().setOutput(targetPortNumber);
                forwardingObjective = genForwarding(selectorBuilder, treatmentBuilder);
                flowObjectiveService.forward(des_devid, forwardingObjective);
            }
        }
        log.info("~~Apply FINAL flow rule on {}, with Specific host~~", des_devid.toString());
    }

    // Generate Forwarding Objective
    private ForwardingObjective genForwarding(TrafficSelector.Builder tsb, TrafficTreatment.Builder ttb){
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
            .withSelector(
                tsb.build()
            )
            .withTreatment(
                ttb.build()
            )
            .withPriority(10)
            .makeTemporary(vlanTimeout)
            .withFlag(ForwardingObjective.Flag.VERSATILE)
            .fromApp(appId)
            .add();
        return forwardingObjective;
    }


    // Config Listener
    private class NameConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                && event.configClass().equals(NameConfig.class)) {
                NameConfig config = cfgService.getConfig(appId, NameConfig.class);
                if (config != null) {
                    JsonNode configNodes = config.node(),
                            edgeSwitchNode = configNodes.findValue("edgeSwitch"),
                            edgeSwitchSubnetNode = configNodes.findValue("edgeSwitchSubnet"),
                            edgeSwitchSegmentIDNode = configNodes.findValue("edgeSwitchSegmentID");
                    // Record the edge switch
                    Iterator<JsonNode> eles = edgeSwitchNode.elements();
                    while (eles.hasNext()){
                        JsonNode now = eles.next();
                        DeviceId.deviceId(now.textValue());
                        edgeSwitchList.add(DeviceId.deviceId(now.textValue()));
                    }

                    // Map Edge Switch and Subnet
                    eles = edgeSwitchSubnetNode.elements();
                    for (int i=0; i<edgeSwitchList.size(); i++){
                        JsonNode now = eles.next();
                        edgeSwitchSubnetMap.put(edgeSwitchList.get(i), now.textValue());

                        // Record IP Prefix
                        String subnets = edgeSwitchSubnetMap.get(edgeSwitchList.get(i)),
                                subnetIP = subnets.split("/")[0],
                                subnetMask = subnets.split("/")[1];
                        int subnetPrefix = Integer.parseInt(subnetMask);
                        IpAddress ipAddress = IpAddress.valueOf(subnetIP);
                        IpPrefix ipPrefix = IpPrefix.valueOf(ipAddress, subnetPrefix);

                        edgeSwitchPrefixMap.put(edgeSwitchList.get(i), ipPrefix);
                    }

                    // Map Edge Switch and Segment ID
                    eles = edgeSwitchSegmentIDNode.elements();
                    for (int i=0; i<edgeSwitchList.size(); i++){
                        JsonNode now = eles.next();
                        edgeSwitchIDMap.put(edgeSwitchList.get(i), now.textValue());
                    }

                    // Map hosts and corresponding MAC address
                    JsonNode cpMac = configNodes.findValue("hosts");
                    Iterator<String> stringEles = cpMac.fieldNames();
                    while (stringEles.hasNext()){
                        String cpValue = stringEles.next(),
                               corresMac = cpMac.findValue(cpValue).textValue();
                        cpMacMap.put(ConnectPoint.deviceConnectPoint(cpValue), MacAddress.valueOf(corresMac));
                    }

                    // output Information for edge switch
                    for (int i=0; i<edgeSwitchList.size(); i++){
                        log.info("EdgeSwitch #{}: {}, subnet: {}, segmentID: {}", i, edgeSwitchList.get(i).toString(), edgeSwitchSubnetMap.get(edgeSwitchList.get(i)), edgeSwitchIDMap.get(edgeSwitchList.get(i)));
                    }
                }
            }
        }
    }
}
