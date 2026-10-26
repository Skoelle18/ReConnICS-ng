package com.pcap.zeek;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;

class ScratchDump {
    @Test
    void dump() throws Exception {
        for (String name : new String[]{"bacnet", "bacnet_control", "bacnet_error", "opcua", "opcua_ipv6", "profinet", "profinet_connect"}) {
            ZeekData d = new ZeekLogReader(false, false).read(Path.of("src/test/resources/real/zeek", name));
            System.out.println("#### " + name + " " + d.stats().toMap().get("logs"));
            d.flows().toList(true).forEach(f -> System.out.println("FLOW " + f.get("client") + ">" + f.get("server") + " " + f.get("protocol") + " " + f.get("port") + " msgs=" + f.get("messages") + " labels=" + f.get("labels") + "\n   ops=" + f.get("operations")));
            d.observations().forEach(o -> System.out.println("OBS " + o.ip() + " " + o.protocolName() + " " + o.identityFields().stream().map(x -> x.kind() + "=" + x.value() + "/" + x.confidence()).toList()));
        }
    }
}
