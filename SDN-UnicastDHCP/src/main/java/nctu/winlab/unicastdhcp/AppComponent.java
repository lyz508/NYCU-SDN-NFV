/*
 * Copyright 2020-present Open Networking Foundation
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
package nctu.winlab.unicastdhcp;

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

// Find Path
import org.onosproject.net.topology.PathService;

// Adding Flow Rule
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.Path;

import com.google.common.collect.Maps;
import java.util.Map; // use on building MacTable
import java.util.Optional; // use to specify if it is nullable
import java.util.Set;
import java.util.ArrayList;
import java.util.List;



/** Sample Network Configuration Service Application */
@Component(immediate = true)
public class AppComponent {

  private final Logger log = LoggerFactory.getLogger(getClass());
  private final NameConfigListener cfgListener = new NameConfigListener();
  private final ConfigFactory<ApplicationId, NameConfig> factory =
      new ConfigFactory<ApplicationId, NameConfig>(
          APP_SUBJECT_FACTORY, NameConfig.class, "UnicastDhcpConfig") {
        @Override
        public NameConfig createConfig() {
          return new NameConfig();
        }
      };
  private UnicastDHCPProcessor unicastProcessor = new UnicastDHCPProcessor();
  private Map< MacAddress, ConnectPoint > recordClients = Maps.newConcurrentMap();
  private int flowRulePiority = 30;
  private int flowRuleTimeout = 30;

  private ApplicationId appId;
  private String[] dhcpLocation = {"None", "None"};

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


  @Activate
  protected void activate() {
    appId = coreService.registerApplication("nctu.winlab.unicastdhcp");

    // Add netcfgs listener
    cfgService.addListener(cfgListener);
    cfgService.registerConfigFactory(factory);

    //Add packetprocessor and packet request
    packetService.addProcessor (
        unicastProcessor,
        PacketProcessor.director(3) // Priority, high number will be processing first
    );
    requestPackets();

    log.info("Started");
  }

  @Deactivate
  protected void deactivate() {
    cfgService.removeListener(cfgListener);
    cfgService.unregisterConfigFactory(factory);

    flowRuleService.removeFlowRulesById(appId); // remove flow rule by application ID
    packetService.removeProcessor(unicastProcessor); // remove processor
    log.info("Stopped");
  }


  /**
    Request Packets
      DHCP: 
        TPv4, 
        Udp (port: 67 for client, 68 for server)
   */
  private void requestPackets(){
    // log.info("Requesting Packet");
    // server
    packetService.requestPackets(
      DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_UDP)
        .matchUdpDst(TpPort.tpPort(67)) // convert integer to TpPort class
        .build(),
      PacketPriority.REACTIVE, appId);
    // client
    packetService.requestPackets(
      DefaultTrafficSelector.builder()
        .matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_UDP)
        .matchUdpDst(TpPort.tpPort(68)) // convert integer to TpPort class
        .build(),
      PacketPriority.REACTIVE, appId);
  }

  /**
    Unicast DHCP Processor
   */
  private class UnicastDHCPProcessor implements PacketProcessor {
    @Override
    public void process (PacketContext pc){ // process inbound packets
      // log.info("Get packet\n");
      if (pc.isHandled()) {
        // log.info("Handled");
        return; // stop when meeeting handled packets 
      }

      // inbound Packet
      InboundPacket inPacket = pc.inPacket();
      Ethernet etherFrame = inPacket.parsed();
      ConnectPoint cp = inPacket.receivedFrom();

      // Filter the packets
      // Do not process LLDP MAC address in any way
      if (etherFrame.getDestinationMAC().isLldp()) {
        // log.info("Get LLDP");
        return;
      }

      if (etherFrame.getEtherType() != Ethernet.TYPE_IPV4){
        // log.info("a");
        return;
      }
      
      IPv4 ipv4Packet = (IPv4) etherFrame.getPayload();
      UDP udpPacket = (UDP) ipv4Packet.getPayload();
      if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_UDP){
        // log.info("b");
        return;
      }
      else if (udpPacket.getDestinationPort() != UDP.DHCP_CLIENT_PORT &&
        udpPacket.getDestinationPort() != UDP.DHCP_SERVER_PORT)
      {
        // log.info("{}", udpPacket.getDestinationPort());
        // log.info("c");
        return;
      }
      

      Set<Path> res;
      boolean isServer = true, sameDevice = true, samePort = true;

      log.info("Unhandled, device: {}/{}\nDHCP server is {}/{}", cp.deviceId().toString(), cp.port().toString(), dhcpLocation[0], dhcpLocation[1]);

      // Judge if is server
      if (cp.deviceId().toString().length() ==  dhcpLocation[0].length())
      {
        for (int i=0; i<cp.deviceId().toString().length(); i++){
          if (cp.deviceId().toString().charAt(i) != dhcpLocation[0].charAt(i)){
            isServer = false;
            sameDevice = false;
            log.info("Device: {} =/= {}", cp.deviceId().toString().charAt(i), dhcpLocation[0].charAt(i));
            break;
          }
        }
      }
      else{
        isServer = false;
        sameDevice = false;
      }
      
      if (cp.port().toString().length() ==  dhcpLocation[1].length())
      {
        for (int i=0; i<cp.port().toString().length(); i++){
          if (cp.port().toString().charAt(i) != dhcpLocation[1].charAt(i)){
            isServer = false;
            samePort = false;
            log.info("Port: {} =/= {}", cp.port().toString().charAt(i), dhcpLocation[1].charAt(i));
            break;
          }
        }
      }
      else{
        isServer = false;
        samePort = false;
      }
      

      // judge EtherType
      if (etherFrame.getEtherType() != Ethernet.TYPE_IPV4)
        return;

      // dealing with server client on same device
      if (sameDevice && !samePort && !isServer)
      {
        log.info("Server and Client are on same device!!");
        recordClients.put(etherFrame.getSourceMAC(), cp); // record in table

        // for client -> server
        FlowRule flowRule = DefaultFlowRule.builder()
          .withSelector(DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .matchEthSrc(etherFrame.getSourceMAC())
            .matchUdpDst(TpPort.tpPort(67))
            .build()
          )
          .withTreatment(DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.portNumber(dhcpLocation[1]))
            .build()
          )
          .withPriority(flowRulePiority)
          .withIdleTimeout(flowRuleTimeout)
          .forDevice(cp.deviceId())
          .fromApp(appId)
          .build();
        flowRuleService.applyFlowRules(flowRule);

        // for server -> client
        flowRule = DefaultFlowRule.builder()
          .withSelector(DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .matchEthDst(pc.inPacket().parsed().getSourceMAC())
            .matchUdpDst(TpPort.tpPort(68))
            .build()
          )
          .withTreatment(DefaultTrafficTreatment.builder()
            .setOutput(cp.port()) // first pacet in will be client
            .build()
          )
          .withPriority(flowRulePiority)
          .withIdleTimeout(flowRuleTimeout)
          .forDevice(cp.deviceId())
          .fromApp(appId)
          .build();
        flowRuleService.applyFlowRules(flowRule);
        // Packet out to server
        packetOut(pc, PortNumber.portNumber(dhcpLocation[1]));

        // End of processing
        return;
      }


      // Based on configuration to figure out Server and Client
      if (isServer){
        log.info("From DHCP Server!");
        isServer = true;

        // Find ConnectPoint via MAC address
        ConnectPoint client_cp = recordClients.get(etherFrame.getDestinationMAC());
        log.info("Target Client MAC address {}", etherFrame.getDestinationMAC());
        if (client_cp != null){
          log.info("Client target: {}/{}", client_cp.deviceId().toString(), client_cp.port().toString());
        }
        else{
          log.info("!!!!!!!!!!There are No Correponding ConnectPoint in Record!!!!!!!!!!!");
          return;
        }

        // Calculate paths via pathService
        res = pathService.getPaths( DeviceId.deviceId(dhcpLocation[0]), client_cp.deviceId() );
        log.info("Got it!!\n from device: {}\n", DeviceId.deviceId(dhcpLocation[0]).toString());
        // Shortest Path existed
        if ( res.size() > 0 ){
          log.info("!!Find A SERVER Path!!");
          ArrayList<Path> arrlst = new ArrayList<>(res);
          List<Link> lks = arrlst.get(0).links();
          
          // Get links in path and print out
          if (lks != null){
            // Print path to log info
            for (int i=0; i<lks.size(); i++){
              ConnectPoint from=lks.get(i).src(), 
                to=lks.get(i).dst();
              log.info("From {}/{} to {}/{}", 
                from.deviceId().toString(), from.port().toString(), 
                to.deviceId().toString(), to.port().toString());
            }
            log.info("!!Start to build flow rule to construct the path!!");

            // Build Flow Rule to construct the path
            installFlowRule(pc, isServer, lks);
          }
        }
        else{
          return;
        }
      }
      else{
        log.info("From DHCP Client!!");
        // Record MAC address and correponding Connectpoint
        recordClients.put(etherFrame.getSourceMAC(), cp);

        // Calculate paths via pathService
        res = pathService.getPaths( cp.deviceId(), DeviceId.deviceId(dhcpLocation[0]) );
        log.info("Got it!!\n from device: {}\n", cp.deviceId().toString());
        // Shortest Path existed
        if ( res.size() > 0 ){
          log.info("!!Find A Client Path!!");
          ArrayList<Path> arrlst = new ArrayList<>(res);
          List<Link> lks = arrlst.get(0).links();
          
          if (lks != null){
            // Print path to log info
            for (int i=0; i<lks.size(); i++){
              ConnectPoint from=lks.get(i).src(), 
                to=lks.get(i).dst();
              log.info("From {}/{} to {}/{}", 
                from.deviceId().toString(), from.port().toString(), 
                to.deviceId().toString(), to.port().toString());
            }
            log.info("!!Start to build flow rule to construct the path!!");

            // Build Flow Rule to construct the path
            installFlowRule(pc, isServer, lks);
          }
        }
        else{
          log.info("!!!!!!?????NO PATH?????!!!!!!");
          return;
        }
      }
    }

    // Install flow rule with a Path List
    private void installFlowRule(PacketContext pc, boolean isServer, List<Link> lks){
      TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
      TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
      DeviceId src_devId = pc.inPacket().receivedFrom().deviceId(),
               des_devid = lks.get(lks.size()-1).dst().deviceId();
      FlowRule flowRule;


      selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
        .matchIPProtocol(IPv4.PROTOCOL_UDP);

      // Depends on whether server or client to select
      if (isServer){
        selectorBuilder.matchEthSrc(pc.inPacket().parsed().getSourceMAC())
          .matchEthSrc(pc.inPacket().parsed().getSourceMAC())
          .matchEthDst(pc.inPacket().parsed().getDestinationMAC())
          .matchUdpDst(TpPort.tpPort(68)); // match server's dst mac address
      }
      else{
        selectorBuilder.matchEthSrc(pc.inPacket().parsed().getSourceMAC())
          .matchUdpDst(TpPort.tpPort(67)); // match client's dst mac address
      }

      // on Links, add flow rules
      // Adding Links: add treatment(output port), add selector(MAC address)
      // Device:
      //  1. Start point: client source and first in-list-from connectpoint (output to its port !)
      //  2. End point: last-in-list-from connectpoint and output to dhcp location port
      //
      // According to the packet types (whether it is server or not), to different work in last
      //    For those packages sent by client, the last output is dhcp port location
      //    For those packages sent by server, parse the MAC address and find corresponding device and port Number


      // Start
      treatmentBuilder.setOutput(lks.get(0).src().port());
      flowRule = genFlowRule(selectorBuilder, treatmentBuilder, src_devId);
      flowRuleService.applyFlowRules(flowRule);
      log.info("~~Apply FIRST output flowRule on {}, output to port {}~~", src_devId.toString(), lks.get(0).src().port().toString());

      // Middle 
      for (int i=1; i<lks.size(); i++){
        ConnectPoint now_dev = lks.get(i).src();
        treatmentBuilder = DefaultTrafficTreatment.builder().setOutput(now_dev.port());
        flowRule = genFlowRule(selectorBuilder, treatmentBuilder, now_dev.deviceId());
        flowRuleService.applyFlowRules(flowRule);
        log.info("~~Apply MIDDLE flow rule on {}, output to port {}~~", now_dev.deviceId().toString(), now_dev.port().toString());
      }

      // Final
      if (!isServer){
        log.info("Final set to the server (from client)");
        treatmentBuilder = DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(dhcpLocation[1]));
        log.info("~~Apply FINAL flow rule on {}, output to port {}~~", des_devid.toString(), PortNumber.portNumber(dhcpLocation[1]).toString());
      }
      else{
        log.info("Final set to the client {} (from server)", 
          recordClients.get(pc.inPacket().parsed().getDestinationMAC()).port().toString());
        treatmentBuilder = DefaultTrafficTreatment.builder().setOutput(recordClients.get(pc.inPacket().parsed().getDestinationMAC()).port());
        log.info("~~Apply FINAL flow rule on {}, output to port {}~~", des_devid.toString(), recordClients.get(pc.inPacket().parsed().getDestinationMAC()).port());
      }
      flowRule = genFlowRule(selectorBuilder, treatmentBuilder, des_devid);
      flowRuleService.applyFlowRules(flowRule);
    }
  }

  /**
   * genFlowRule
   * @param tsb: traffic selector builder
   * @param ttb: traffic treatment builder
   * @param deviceId: Target device Id
   * @return: built Flow rule
   */
  private FlowRule genFlowRule(TrafficSelector.Builder tsb, TrafficTreatment.Builder ttb,
    DeviceId deviceId){
      FlowRule flowRule = DefaultFlowRule.builder()
        .withSelector(
          tsb.build()
        )
        .withTreatment(
          ttb.build()
        )
        .withPriority(flowRulePiority)
        .withIdleTimeout(flowRuleTimeout)
        .forDevice(deviceId)
        .fromApp(appId)
        .build();
      return flowRule;
  }

  /**
   * Packet Out
   *  Output Packets to specified port
   */
  private void packetOut(PacketContext pc, PortNumber target){
    pc.treatmentBuilder().setOutput(target);
    pc.send(); // packet out
  }


  /**
    Config Listener
   */
  private class NameConfigListener implements NetworkConfigListener {
    @Override
    public void event(NetworkConfigEvent event) {
      if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
          && event.configClass().equals(NameConfig.class)) {
        NameConfig config = cfgService.getConfig(appId, NameConfig.class);
        if (config != null) {
          dhcpLocation[0] = config.getSwitch();
          dhcpLocation[1] = config.getSwitchPort();
          log.info("The Location has been updated, switch: {}, port: {}", dhcpLocation[0], dhcpLocation[1]); // set DHCP server location
        }
      }
    }
  }
}