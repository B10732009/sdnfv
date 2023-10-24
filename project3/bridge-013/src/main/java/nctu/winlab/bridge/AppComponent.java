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

package nctu.winlab.bridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.util.KryoNamespace;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;

import java.util.HashMap;
import java.util.Map;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true) 
public class AppComponent { 

    private Logger log;
    private EventuallyConsistentMap<DeviceId, Map<MacAddress, PortNumber>> macAddressTable;
    private MyPacketProcessor myPacketprocessor;
    private ApplicationId appId;

    // to use services of ONOS
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    
    // to trace the components
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;
    
    // to intercept and handle packets
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    // to install new flow rules
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    // storage
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    @Activate
    protected void activate() {
        // initialize logger
        log = LoggerFactory.getLogger(getClass());

        // initialize MAC address table with serialized map
        KryoNamespace.Builder metricSerializer = KryoNamespace.newBuilder()
            .register(MultiValuedTimestamp.class);
        macAddressTable =  storageService.<DeviceId, Map<MacAddress, PortNumber>>eventuallyConsistentMapBuilder()
                .withName("macAddressTable")
                .withSerializer(metricSerializer)
                .withTimestampProvider((key, metricsData) -> new
                    MultiValuedTimestamp<>(new WallClockTimestamp(), System.nanoTime()))
                .build();

        // initialize and add processor to handle packets
        myPacketprocessor = new MyPacketProcessor();
        packetService.addProcessor(myPacketprocessor, PacketProcessor.director(2));

        // initialize application ID
        appId = coreService.registerApplication("nctu.winlab.bridge");
        
        // set criteria to intercept packets
        requestIntercepts();
        log.info(String.format("Started %s.", appId.toString()));
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        log.info(String.format("Stopped %s.", appId.toString()));
    }

    private void requestIntercepts() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .build();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .build();
        packetService.cancelPackets(selector, PacketPriority.REACTIVE, appId);
    }

    private class MyPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            // check if the packet has been handled
            if (context.isHandled()) {
		        return;
            }

            InboundPacket packet = context.inPacket();
            MacAddress srcMacAddress = packet.parsed().getSourceMAC();
            MacAddress dstMacAddress = packet.parsed().getDestinationMAC();
            DeviceId deviceId = packet.receivedFrom().deviceId();
            PortNumber inPortNumber = packet.receivedFrom().port();
            
            log.info(String.format("Add an entry to the port table of `%s`. MAC address: `%s` => Port: `%s`.", 
                deviceId.toString(), srcMacAddress.toString(), inPortNumber.toString()));
            packetIn(deviceId, srcMacAddress, inPortNumber);
            
            Map<MacAddress, PortNumber> subMacAddressTable = macAddressTable.get(deviceId);
            if(subMacAddressTable.containsKey(dstMacAddress)) {
                log.info(String.format("MAC address `%s` is matched on `%s`. Install a flow rule.", 
                    dstMacAddress.toString(), deviceId.toString()));
                PortNumber outPortNumber = subMacAddressTable.get(dstMacAddress);
                packetOut(context, outPortNumber);
                installFlowRule(context, outPortNumber);
            }
            else {
                log.info(String.format("MAC address `%s` is missed on `%s`. Flood the packet.", 
                    dstMacAddress.toString(), deviceId.toString()));
                packetOut(context, PortNumber.FLOOD);
            }
        }
    }

    private void packetIn(DeviceId deviceId, MacAddress srcMacAddress, PortNumber inPortNumber) {
        // update MAC address table with source MAC address and incoming port
        if (macAddressTable.containsKey(deviceId)) {
            Map<MacAddress, PortNumber> subMacAddressTable = macAddressTable.get(deviceId);
            subMacAddressTable.put(srcMacAddress, inPortNumber);
        }
        else { 
            Map<MacAddress, PortNumber> newSubMacAddressTable = new HashMap<MacAddress, PortNumber>();
            newSubMacAddressTable.put(srcMacAddress, inPortNumber);
            macAddressTable.put(deviceId, newSubMacAddressTable);
        }
    }

    private void packetOut(PacketContext context, PortNumber outPortNumber) {
        context.treatmentBuilder().setOutput(outPortNumber);
        context.send();
    }

    private void installFlowRule(PacketContext context, PortNumber outPortNumber) {
        InboundPacket packet = context.inPacket();
        MacAddress srcMacAddress = packet.parsed().getSourceMAC();
        MacAddress dstMacAddress = packet.parsed().getDestinationMAC();
        DeviceId deviceId = packet.receivedFrom().deviceId();
        int priority = 30;
        int timeout = 30;

        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchEthSrc(srcMacAddress)
            .matchEthDst(dstMacAddress)
            .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .setOutput(outPortNumber)
            .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
            .withSelector(selector)
            .withTreatment(treatment)
            .withPriority(priority)
            .makeTemporary(timeout)
            .withFlag(ForwardingObjective.Flag.VERSATILE)
            .fromApp(appId)
            .add();

        flowObjectiveService.forward(deviceId, forwardingObjective);
    }
}
