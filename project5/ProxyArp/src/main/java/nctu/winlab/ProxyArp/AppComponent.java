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
package nctu.winlab.ProxyArp;

import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ARP;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private Map<Ip4Address, MacAddress> arpTbl = new HashMap<>();
    private MyPacketProcessor processor = new MyPacketProcessor();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        packetService.addProcessor(processor, PacketProcessor.director(3));
        log.info("Started {}.", appId);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        log.info("Stopped {}.", appId);
    }

    private class MyPacketProcessor implements PacketProcessor {
        @Override
		public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket inPkt = context.inPacket();
            if (inPkt == null) {
                return;
            }

            Ethernet ethPkt = inPkt.parsed();
            if (ethPkt == null || 
                ethPkt.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arpPkt = (ARP)ethPkt.getPayload();
            if (arpPkt == null) {
                return;
            }

            Ip4Address sip = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
            Ip4Address tip = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
            MacAddress smac = ethPkt.getSourceMAC();
            MacAddress tmac = ethPkt.getDestinationMAC();

            DeviceId did = inPkt.receivedFrom().deviceId();
            PortNumber port = inPkt.receivedFrom().port();

            if (arpPkt.getOpCode() == (short)0x1) { // receive ARP request
                if (arpTbl.containsKey(tip)) { // ARP table hit, return the target MAC address
                    tmac = arpTbl.get(tip);
                    Ethernet repPkt = createPacket((short)0x2, tip, tmac, sip, smac);
                    sendPacket(did, port, repPkt);
                    log.info("TABLE HIT. Requested MAC = {}", tmac);
                }
                else { // ARP table miss, flood the ARP packet
                    Ethernet reqPkt = createPacket((short)0x1, sip, smac, tip, tmac);
                    Iterable<ConnectPoint> eps = edgePortService.getEdgePoints();
                    for (ConnectPoint ep: eps) {
                        if (!(ep.deviceId().equals(did) && ep.port().equals(port))) {
                            sendPacket(ep.deviceId(), ep.port(), reqPkt);
                        }
                    }
                    log.info("TABLE MISS. Send request to edge ports");
                }
            }
            else if (arpPkt.getOpCode() == (short)0x2) { // recieve ARP reply
                arpTbl.put(sip, smac);
                log.info("RECV REPLY. Requested MAC = {}", smac);
            }
        }

        private Ethernet createPacket(short op, Ip4Address sip, MacAddress smac, 
                                                Ip4Address tip, MacAddress tmac) {
            ARP arpPkt = new ARP();
            arpPkt.setHardwareType((short)0x0001);
            arpPkt.setProtocolType((short)0x0800);
            arpPkt.setHardwareAddressLength((byte)6);
            arpPkt.setProtocolAddressLength((byte)4);
            arpPkt.setOpCode(op);
            arpPkt.setSenderHardwareAddress(smac.toBytes());
            arpPkt.setSenderProtocolAddress(sip.toInt());
            arpPkt.setTargetHardwareAddress(tmac.toBytes());
            arpPkt.setTargetProtocolAddress(tip.toInt());

            Ethernet ethPkt = new Ethernet();
            ethPkt.setEtherType(Ethernet.TYPE_ARP);
            ethPkt.setSourceMACAddress(smac);
            ethPkt.setDestinationMACAddress(tmac);
            ethPkt.setPayload(arpPkt);
                
            return ethPkt;
        }

        private void sendPacket(DeviceId deviceId, PortNumber portNumber, Ethernet ethPacket) {
            TrafficTreatment trafficTreatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

            OutboundPacket outPkt = new DefaultOutboundPacket(deviceId, trafficTreatment, 
                ByteBuffer.wrap(ethPacket.serialize()));

            packetService.emit(outPkt);
        }
    }
}
