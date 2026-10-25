package com.pcap.zeek;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The reader on logs Zeek 8.0.9 and the CISA ICSNPP packages really wrote (src/test/resources/real/zeek, provenance in
 * src/test/resources/real/PROVENANCE.md). Each test pins a column that the first, hand-made fixtures got wrong.
 */
class ZeekRealLogsTest {
    private static ZeekData read(String name) throws ZeekException {
        return new ZeekLogReader(false, false).read(Path.of("src/test/resources/real/zeek", name));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> ops(ZeekData d) {
        return d.flows().toList(true).stream().flatMap(f -> ((List<Map<String, Object>>) f.getOrDefault("operations", List.of())).stream()).toList();
    }

    private static List<Map<String, Object>> named(ZeekData d, String function) {
        return ops(d).stream().filter(o -> function.equals(o.get("function"))).toList();
    }

    @Test
    void s7ComplusRowsAreReadFromOpcodeName() throws Exception {
        ZeekData d = read("s7plus");
        assertEquals(0, d.stats().totalSkipped(), "s7comm_plus.log has opcode_name, not function_name");
        assertFalse(named(d, "S7plus opcode-0x69").isEmpty(), ops(d).toString());
        assertFalse(named(d, "S7plus opcode-0x81").isEmpty());
    }

    @Test
    void s7BlockTransfersAreNamedFromFunctionNameAndCountedOnce() throws Exception {
        ZeekData d = read("s7");
        assertEquals(0, d.stats().totalSkipped());
        var up = named(d, "Start Upload");
        assertEquals(1, up.size(), "s7comm.log and s7comm_upload_download.log describe the same 4 jobs: " + up);
        assertEquals(4L, up.get(0).get("count"));
        assertEquals("System Data Block 00000", up.get(0).get("object"));
        assertTrue(((Map<?, ?>) up.get(0).get("statuses")).keySet().toString().contains("status:"), "the acknowledgement's error class lands on it");
        assertTrue(named(d, "Block transfer").isEmpty());
        var szl = ops(d).stream().filter(o -> "Read SZL".equals(o.get("function")) && "Module identification".equals(o.get("object"))).toList();
        assertEquals(1, szl.size());
        assertEquals(17L, szl.get(0).get("address"));
    }

    @Test
    void cipInstanceIdsAreHexStringsAndUnknownClassesKeepTheirId() throws Exception {
        ZeekData d = read("enip");
        assertEquals(0, d.stats().totalSkipped());
        var identity = ops(d).stream().filter(o -> "Get Attribute List".equals(o.get("function")) && "Identity".equals(o.get("object"))).toList();
        assertFalse(identity.isEmpty(), ops(d).toString());
        assertEquals(1L, identity.get(0).get("address"), "instance_id \"0x01\" is instance 1");
        assertTrue(ops(d).stream().anyMatch(o -> String.valueOf(o.get("object")).startsWith("class 0x")), "class_name \"unknown\" is replaced by the class id");
        assertTrue(ops(d).stream().noneMatch(o -> "unknown".equals(o.get("object"))));
    }

    @Test
    void modbusFc22AndFc23GetTheirAddressFromThePerFunctionLogs() throws Exception {
        ZeekData d = read("modbus");
        assertEquals(0, d.stats().totalSkipped());
        var rw = named(d, "FC23 read/write multiple registers");
        assertEquals(2, rw.size(), "two transactions with different write sizes: " + rw);
        assertTrue(rw.stream().allMatch(o -> Long.valueOf(2).equals(o.get("address")) && Long.valueOf(6).equals(o.get("unit"))), rw.toString());
        assertTrue(rw.stream().anyMatch(o -> Long.valueOf(4).equals(o.get("quantity"))));
        assertTrue(rw.stream().allMatch(o -> ((Map<?, ?>) o.get("statuses")).containsKey("ok")));
        var mask = named(d, "FC22 mask write register");
        assertEquals(1, mask.size());
        assertEquals(10L, mask.get(0).get("address"));
        assertEquals(2L, mask.get(0).get("count"), "counted once per transaction, not once per log");
    }

    @Test
    void dnp3IinIsOneNumberWithIin1InTheHighByte() throws Exception {
        // identical to Wireshark's dnp3.al.iin for all 53 replies of this capture (checked with tshark 4.4.19)
        ZeekData d = read("dnp3_iin");
        assertEquals(0, d.stats().totalSkipped());
        Set<String> iin = new TreeSet<>();
        for (var o : ops(d)) {
            if (o.get("statuses") instanceof Map<?, ?> m) {
                m.keySet().stream().map(String::valueOf).filter(k -> k.startsWith("iin: ")).forEach(iin::add);
            }
        }
        assertEquals(Set.of("iin: broadcast", "iin: class 2 events", "iin: device restart", "iin: function code not supported", "iin: need time"), iin,
                "iin values seen: 0x0100 0x1000 0x1001 0x8000 0x9000 0x9501 -> broadcast, need time, fc not supported, device restart, class 2");
    }

    @Test
    void dnp3ControlBlocksCarryTheOutstationsStatus() throws Exception {
        ZeekData d = read("dnp3_control");
        assertEquals(0, d.stats().totalSkipped());
        var sel = ops(d).stream().filter(o -> "FC3 select".equals(o.get("function")) && "Control Relay Output Block".equals(o.get("object"))).toList();
        assertEquals(1, sel.size(), sel.toString());
        assertEquals(34463L, sel.get(0).get("address"));
        assertTrue(((Map<?, ?>) sel.get(0).get("statuses")).containsKey("status: not supported"));
    }
}
