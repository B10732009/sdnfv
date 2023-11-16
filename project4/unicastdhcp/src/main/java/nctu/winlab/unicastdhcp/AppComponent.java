/*
 * Copyright 2023-present Open Networking Foundation
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

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.FilteredConnectPoint;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;
    private String serverLocation;

    private MyNetworkConfigListener cfgListener = new MyNetworkConfigListener();
    private MyPacketProcessor processor = new MyPacketProcessor();

    private ConfigFactory<ApplicationId, ServerLocationConfig> factory 
        = new ConfigFactory<ApplicationId, ServerLocationConfig>(APP_SUBJECT_FACTORY, ServerLocationConfig.class, "UnicastDhcpConfig") {
            @Override
            public ServerLocationConfig createConfig() {
                return new ServerLocationConfig();
        }
    };

    private int priority = 30;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry ncfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.unicastdhcp");
        ncfgService.addListener(cfgListener);
        ncfgService.registerConfigFactory(factory);
        packetService.addProcessor(processor, PacketProcessor.director(3));
        requestIntercepts();
        log.info("Started {}.", appId.toString());
    }

    @Deactivate
    protected void deactivate() {
        ncfgService.removeListener(cfgListener);
        ncfgService.unregisterConfigFactory(factory);
        packetService.removeProcessor(processor);
        withdrawIntercepts();
        log.info("Stopped {}.", appId.toString());
    }

    private void requestIntercepts() {
        TrafficSelector selector =  DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector selector =  DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .build();
        packetService.cancelPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private class MyNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED) && 
                 event.configClass().equals(ServerLocationConfig.class)) {
                ServerLocationConfig config = ncfgService.getConfig(appId, ServerLocationConfig.class);
                if (config != null) {
                    serverLocation = config.serverLocation();
                    String[] splitted = serverLocation.split("/");
                    log.info("DHCP server is connected to `{}`, port `{}`", 
                        splitted[0], splitted[1]);
                }
            }
        }
    }

    private class MyPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket packet = context.inPacket();
            Ethernet ethPacket = packet.parsed();
            if (ethPacket.getEtherType() != Ethernet.TYPE_IPV4) {
                return;
            }

            IPv4 ipv4Packet = (IPv4)ethPacket.getPayload();
            if (ipv4Packet.getProtocol() != IPv4.PROTOCOL_UDP) {
                return;
            }

            UDP udpPacket = (UDP)ipv4Packet.getPayload();
            if (!(udpPacket.getSourcePort() == UDP.DHCP_CLIENT_PORT && udpPacket.getDestinationPort() == UDP.DHCP_SERVER_PORT) &&
                !(udpPacket.getSourcePort() == UDP.DHCP_SERVER_PORT && udpPacket.getDestinationPort() == UDP.DHCP_CLIENT_PORT)) {
                return;
            }

            DHCP dhcpPacket = (DHCP)udpPacket.getPayload();
            if (dhcpPacket.getPacketType() == DHCP.MsgType.DHCPDISCOVER || 
                dhcpPacket.getPacketType() == DHCP.MsgType.DHCPREQUEST) {
                ConnectPoint serverConnectpoint = ConnectPoint.deviceConnectPoint(serverLocation);
                ConnectPoint clientConnectPoint = packet.receivedFrom();
                MacAddress clientMacAddress = ethPacket.getSourceMAC();
                createIntents(serverConnectpoint, clientConnectPoint, clientMacAddress);
            }
        }

        private void createIntents(ConnectPoint serverConnectPoint, ConnectPoint clientConnectPoint, MacAddress clientMacAddress) {
            // create intent from client to server
            TrafficSelector selectorToServer = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
                .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
                .matchEthSrc(clientMacAddress)
                .build();
            
            TrafficTreatment treatmentToServer = DefaultTrafficTreatment.builder()
                .build();

            PointToPointIntent intentToServer = PointToPointIntent.builder()
                .appId(appId)
                .filteredIngressPoint(new FilteredConnectPoint(clientConnectPoint))
                .filteredEgressPoint(new FilteredConnectPoint(serverConnectPoint))
                .selector(selectorToServer)
                .treatment(treatmentToServer)
                .priority(priority)
                .build();

            intentService.submit(intentToServer);

            log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted.",
                clientConnectPoint.deviceId(), clientConnectPoint.port(), 
                serverConnectPoint.deviceId(), serverConnectPoint.port());

            // create intent from server to client
            TrafficSelector selectorToClient = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
                .matchUdpDst(TpPort.tpPort(UDP.DHCP_CLIENT_PORT))
                .matchEthDst(clientMacAddress)
                .build();

            TrafficTreatment treatmentToClient = DefaultTrafficTreatment.builder()
                .build();

            PointToPointIntent intentToClient = PointToPointIntent.builder()
                    .appId(appId)
                    .filteredIngressPoint(new FilteredConnectPoint(serverConnectPoint))
                    .filteredEgressPoint(new FilteredConnectPoint(clientConnectPoint))
                    .selector(selectorToClient)
                    .treatment(treatmentToClient)
                    .priority(priority)
                    .build();

            intentService.submit(intentToClient);

            log.info("Intent `{}`, port `{}` => `{}`, port `{}` is submitted.",
                serverConnectPoint.deviceId(), serverConnectPoint.port(), 
                clientConnectPoint.deviceId(), clientConnectPoint.port());
        }
    }
}
