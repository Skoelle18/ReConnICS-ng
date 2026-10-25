package com.pcap.zeek;

import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Modbus, DNP3, S7, EtherNet/IP and CIP rows as the ICSNPP packages write them (field names from each package's README and from
 * the real rows in src/test/resources/zeek), written out by hand so each case is one or two lines.
 */
class ZeekIcsLogsTest {
    @TempDir
    Path tmp;

    private ZeekData read(Map<String, String> logs) throws IOException, ZeekException {
        Path dir = Files.createTempDirectory(tmp, "ics");
        for (var e : logs.entrySet()) {
            Files.writeString(dir.resolve(e.getKey()), e.getValue());
        }
        return new ZeekLogReader(false, false).read(dir);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> flow(ZeekData d, String protocol) {
        return d.flows().toList(true).stream().filter(f -> protocol.equals(f.get("protocol"))).findFirst()
                .orElseThrow(() -> new AssertionError("no " + protocol + " flow in " + d.flows().toList(true)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> op(Map<String, Object> flow, String function) {
        return ((List<Map<String, Object>>) flow.get("operations")).stream().filter(o -> function.equals(o.get("function"))).findFirst()
                .orElseThrow(() -> new AssertionError("no operation " + function + " in " + flow.get("operations")));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Long> labels(Map<String, Object> flow) {
        return (Map<String, Long>) flow.get("labels");
    }

    private static final String ID = "\"uid\":\"C1\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":40000,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":";

    // ---------------------------------------------------------------- Modbus

    @Test
    void functionNamesGiveTheBaseFunctionAndExceptionResponsesNameTheirCode() {
        assertEquals("FC3 read holding registers", ZeekNames.modbusFunction("READ_HOLDING_REGISTERS_EXCEPTION"));
        assertEquals("FC17 report server id", ZeekNames.modbusFunction("REPORT_SLAVE_ID"));
        assertEquals("FC43 encapsulated interface transport", ZeekNames.modbusFunction("ENCAP_INTERFACE_TRANSPORT"));
        // ICSNPP names a code it has no table entry for "unknown-<n>"; an exception is the function code with bit 7 set
        assertEquals(17, ZeekNames.modbusCode("unknown-145"));
        assertTrue(ZeekNames.modbusIsException("unknown-145"));
        assertFalse(ZeekNames.modbusIsException("unknown-17"));
        assertEquals("FC0 invalid function code", ZeekNames.modbusFunction("unknown-0"));
        assertEquals("FC0 invalid function code", ZeekNames.modbusFunction("unknown-128"));
        assertTrue(ZeekNames.modbusIsException("unknown-128"));
        assertEquals("FC100 user-defined", ZeekNames.modbusFunction("unknown-100"));
        assertEquals("illegal data address", ZeekNames.modbusException("ILLEGAL_DATA_ADDRESS"));
        assertEquals("illegal data address", ZeekNames.modbusException("2"));
        assertEquals("gateway target device failed to respond", ZeekNames.modbusException("11"));
        assertNull(ZeekNames.modbusException(""));
        assertEquals("read", ZeekNames.modbusAccess(17, "REPORT_SLAVE_ID"), "reporting the server id changes nothing");
        assertEquals("write", ZeekNames.modbusAccess(23, "READ_WRITE_MULTIPLE_REGISTERS"));
    }

    @Test
    void modbusLogLabelsNeverShowUnknownDashNumber() throws Exception {
        String rows = "{" + ID + "502,\"tid\":1,\"unit\":1,\"func\":\"unknown-0\",\"pdu_type\":\"REQ\"}\n"
                + "{" + ID + "502,\"tid\":1,\"unit\":1,\"func\":\"unknown-128\",\"pdu_type\":\"RESP\",\"exception\":\"ILLEGAL_FUNCTION\"}\n"
                + "{" + ID + "502,\"tid\":2,\"unit\":1,\"func\":\"unknown-145\",\"pdu_type\":\"RESP\"}\n"
                + "{" + ID + "502,\"tid\":3,\"unit\":1,\"func\":\"REPORT_SLAVE_ID\",\"pdu_type\":\"REQ\"}\n"
                + "{" + ID + "502,\"tid\":4,\"unit\":1,\"func\":\"READ_HOLDING_REGISTERS_EXCEPTION\",\"pdu_type\":\"RESP\",\"exception\":\"ILLEGAL_DATA_ADDRESS\"}\n";
        var labels = labels(flow(read(Map.of("modbus.log", rows)), "modbus")).keySet();
        assertTrue(labels.stream().noneMatch(l -> l.contains("unknown")), labels.toString());
        assertTrue(labels.contains("Modbus FC0"), labels.toString());
        assertTrue(labels.contains("Modbus FC0 exception: illegal function"), labels.toString());
        assertTrue(labels.contains("Modbus FC17 exception"), labels.toString());
        assertTrue(labels.contains("Modbus FC17"), labels.toString());
        assertTrue(labels.contains("Modbus FC3 exception: illegal data address"), labels.toString());
    }

    @Test
    void detailedRowsCarryUnitSubfunctionAndOutcome() throws Exception {
        String rows = "{" + ID + "502,\"tid\":1,\"unit\":7,\"func\":\"READ_HOLDING_REGISTERS\",\"matched\":true,\"address\":10,\"quantity\":2,\"response_values\":[5,6]}\n"
                + "{" + ID + "502,\"tid\":2,\"unit\":7,\"func\":\"READ_HOLDING_REGISTERS\",\"matched\":true,\"address\":10,\"quantity\":2,\"response_values\":[5,6]}\n"
                + "{" + ID + "502,\"tid\":3,\"unit\":7,\"func\":\"READ_HOLDING_REGISTERS\",\"matched\":true,\"address\":900,\"quantity\":2,\"exception_code\":\"ILLEGAL_DATA_ADDRESS\"}\n"
                + "{" + ID + "502,\"tid\":4,\"unit\":8,\"func\":\"READ_HOLDING_REGISTERS\",\"matched\":true,\"address\":10,\"quantity\":2}\n"
                + "{" + ID + "502,\"tid\":5,\"unit\":7,\"func\":\"DIAGNOSTICS\",\"matched\":true,\"request_subfunction_code\":\"Force Listen Only Mode\"}\n"
                + "{" + ID + "502,\"tid\":6,\"unit\":7,\"func\":\"WRITE_SINGLE_COIL\",\"matched\":false,\"address\":3,\"quantity\":1,\"request_values\":[65280]}\n";
        var f = flow(read(Map.of("modbus_detailed.log", rows)), "modbus");
        @SuppressWarnings("unchecked") var ops = (List<Map<String, Object>>) f.get("operations");
        assertEquals(5, ops.size(), "unit 7 and unit 8 are different rows: " + ops);
        var ok = ops.stream().filter(o -> Long.valueOf(10).equals(o.get("address")) && Long.valueOf(7).equals(o.get("unit"))).findFirst().orElseThrow();
        assertEquals(2L, ok.get("count"));
        assertEquals(Map.of("ok", 2L), ok.get("statuses"));
        var bad = ops.stream().filter(o -> Long.valueOf(900).equals(o.get("address"))).findFirst().orElseThrow();
        assertEquals(Map.of("exception: illegal data address", 1L), bad.get("statuses"));
        assertEquals("Force Listen Only Mode", op(f, "FC8 diagnostics").get("object"));
        assertEquals(Map.of("unanswered", 1L), op(f, "FC5 write single coil").get("statuses"));
        assertEquals("write", op(f, "FC5 write single coil").get("access"));
    }

    @Test
    void perFunctionLogsAddFc22AndFc23UnlessDetailedAlreadyHasThem() throws Exception {
        String mask = "{" + ID + "502,\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":502,"
                + "\"modbus_detailed_link_id\":\"L1\",\"tid\":1,\"unit\":1,\"func\":\"MASK_WRITE_REGISTER\",\"request_response\":\"REQUEST\",\"address\":8,\"and_mask\":255,\"or_mask\":2}\n"
                + "{" + ID + "502,\"is_orig\":false,\"source_h\":\"10.0.0.9\",\"source_p\":502,\"destination_h\":\"10.0.0.5\",\"destination_p\":40000,"
                + "\"modbus_detailed_link_id\":\"L1\",\"tid\":1,\"unit\":1,\"func\":\"MASK_WRITE_REGISTER\",\"request_response\":\"RESPONSE\",\"address\":8,\"and_mask\":255,\"or_mask\":2}\n";
        String rw = "{" + ID + "502,\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":502,"
                + "\"modbus_detailed_link_id\":\"L2\",\"tid\":2,\"unit\":1,\"func\":\"READ_WRITE_MULTIPLE_REGISTERS\",\"request_response\":\"REQUEST\","
                + "\"write_start_address\":20,\"write_registers\":[1,2],\"read_start_address\":0,\"read_quantity\":4}\n";
        var f = flow(read(Map.of("modbus_mask_write_register.log", mask, "modbus_read_write_multiple_registers.log", rw)), "modbus");
        var m = op(f, "FC22 mask write register");
        assertEquals(1L, m.get("count"), "the response row is the same transaction");
        assertEquals(8L, m.get("address"));
        assertEquals(List.of(255L, 2L), m.get("sampleValues"));
        var x = op(f, "FC23 read/write multiple registers");
        assertEquals(20L, x.get("address"));
        assertEquals(List.of(1L, 2L), x.get("sampleValues"));

        // the same transaction in modbus_detailed.log is not counted twice
        String detailed = "{" + ID + "502,\"modbus_detailed_link_id\":\"L1\",\"unit\":1,\"func\":\"MASK_WRITE_REGISTER\",\"matched\":true,\"address\":8}\n";
        var both = flow(read(Map.of("modbus_detailed.log", detailed, "modbus_mask_write_register.log", mask)), "modbus");
        assertEquals(1, ((List<?>) both.get("operations")).size(), both.toString());
    }

    @Test
    void deviceIdentificationRequestsBecomeAnOperation() throws Exception {
        String req = "{" + ID + "502,\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":502,"
                + "\"tid\":1,\"unit\":255,\"func\":\"ENCAP_INTERFACE_TRANSPORT\",\"request_response\":\"REQUEST\",\"mei_type\":\"READ-DEVICE-IDENTIFICATION\","
                + "\"device_id_code\":2,\"object_id_code\":\"0x00\",\"object_id\":\"Basic Device Identification\"}\n";
        var o = op(flow(read(Map.of("modbus_read_device_identification.log", req)), "modbus"), "FC43/14 read device identification");
        assertEquals("read", o.get("access"));
        assertEquals("Basic Device Identification", o.get("object"));
        assertEquals(255L, o.get("unit"));
    }

    // ---------------------------------------------------------------- DNP3

    private static final String D = "\"uid\":\"Cd\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":40000,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":20000,";

    @Test
    void iinAndStatusCodesBecomeLabels() {
        assertEquals(List.of("need time"), ZeekNames.dnp3Iin(0x1000));
        assertEquals(List.of("device restart", "object unknown"), ZeekNames.dnp3Iin(0x8002));
        assertEquals(List.of(), ZeekNames.dnp3Iin(0));
        assertEquals(List.of(), ZeekNames.dnp3Iin(-1));
        assertTrue(ZeekNames.dnp3IinIsError("parameter error"));
        assertFalse(ZeekNames.dnp3IinIsError("class 1 events"));
        assertEquals("not supported", ZeekNames.dnp3Status("Not Supported"));
        assertEquals("not supported", ZeekNames.dnp3Status("NOT_SUPPORTED"));
        assertEquals("not authorized", ZeekNames.dnp3Status("9"));
        assertEquals("success", ZeekNames.dnp3Status("0"));
    }

    @Test
    void dnp3IinGoesOnTheRequestAndAnUnsolicitedReplyIsItsOwnOperation() throws Exception {
        String rows = "{" + D + "\"fc_request\":\"READ\",\"fc_reply\":\"RESPONSE\",\"iin\":0}\n"
                + "{" + D + "\"fc_request\":\"READ\",\"fc_reply\":\"RESPONSE\",\"iin\":4098}\n"          // need time + object unknown
                + "{" + D + "\"fc_reply\":\"UNSOLICITED_RESPONSE\",\"iin\":512}\n";                      // class 2 events? no: IIN1 bit1 = class 1 events
        var f = flow(read(Map.of("dnp3.log", rows)), "dnp3");
        var read = op(f, "FC1 read");
        assertEquals(2L, read.get("count"));
        @SuppressWarnings("unchecked") var st = (Map<String, Long>) read.get("statuses");
        assertEquals(1L, st.get("ok"));
        assertEquals(1L, st.get("iin: object unknown"), "errors are listed before routine flags: " + st);
        assertEquals(1L, st.get("iin: need time"));
        assertEquals(Map.of("iin: class 1 events", 1L), op(f, "FC130 unsolicited response").get("statuses"));
    }

    @Test
    void anOutstationThatOpenedTheConnectionIsStillTheServer() throws Exception {
        // the TCP originator uses port 20000: it is the outstation, whatever side connected
        String rows = "{\"uid\":\"Co\",\"id.orig_h\":\"10.0.0.9\",\"id.orig_p\":20000,\"id.resp_h\":\"10.0.0.5\",\"id.resp_p\":51000,\"fc_request\":\"READ\",\"fc_reply\":\"RESPONSE\",\"iin\":0}\n";
        var f = flow(read(Map.of("dnp3.log", rows)), "dnp3");
        assertEquals("10.0.0.5", f.get("client"));
        assertEquals("10.0.0.9", f.get("server"));
        assertEquals("20000/tcp", f.get("port"));
    }

    @Test
    void dnp3ControlStatusLandsOnTheRequestItAnswers() throws Exception {
        String src = "\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":20000,";
        String dst = "\"is_orig\":false,\"source_h\":\"10.0.0.9\",\"source_p\":20000,\"destination_h\":\"10.0.0.5\",\"destination_p\":40000,";
        String crob = "\"block_type\":\"Control Relay Output Block\",\"index_number\":3,\"trip_control_code\":\"Nul\",\"operation_type\":\"Latch On\",\"clear_bit\":false,\"execute_count\":1,\"on_time\":0,\"off_time\":0";
        String rows = "{" + D + src + "\"function_code\":\"SELECT\"," + crob + "}\n"
                + "{" + D + dst + "\"function_code\":\"RESPONSE\"," + crob + ",\"status_code\":\"Success\"}\n"
                + "{" + D + src + "\"function_code\":\"OPERATE\"," + crob + "}\n"
                + "{" + D + dst + "\"function_code\":\"RESPONSE\"," + crob + ",\"status_code\":\"Not Supported\"}\n"
                + "{" + D + src + "\"function_code\":\"OPERATE\"," + crob + "}\n"
                + "{" + D + dst + "\"function_code\":\"RESPONSE\"," + crob + ",\"status_code\":\"Not Supported\"}\n";
        var f = flow(read(Map.of("dnp3_control.log", rows)), "dnp3");
        @SuppressWarnings("unchecked") var ops = (List<Map<String, Object>>) f.get("operations");
        assertEquals(2, ops.size(), "the answers are not operations of their own: " + ops);
        var select = op(f, "FC3 select");
        assertEquals(Map.of("ok", 1L), select.get("statuses"));
        var operate = op(f, "FC4 operate");
        assertEquals(2L, operate.get("count"));
        assertEquals(Map.of("status: not supported", 2L), operate.get("statuses"));
        assertEquals("control", operate.get("access"));
        assertEquals("Control Relay Output Block", operate.get("object"));
        assertEquals(3L, operate.get("address"));
        assertEquals(List.of("Latch On"), operate.get("sampleValues"), "one sample per distinct label, and Nul trip code is no information");
    }

    @Test
    void dnp3ObjectRangesBecomeQuantitiesAndLongNamesSurvive() throws Exception {
        String src = "\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":20000,";
        String rows = "{" + D + src + "\"function_code\":\"READ\",\"object_type\":\"Binary Input Change Default Variation\",\"object_count\":1,\"range_low\":5,\"range_high\":12}\n"
                + "{" + D + src + "\"function_code\":\"OPEN_FILE\",\"object_type\":\"File Control - File Command\",\"object_count\":1}\n";
        var f = flow(read(Map.of("dnp3_objects.log", rows)), "dnp3");
        var r = op(f, "FC1 read");
        assertEquals("Binary Input Change Default Variation", r.get("object"), "37 characters, not cut at 32");
        assertEquals(5L, r.get("address"));
        assertEquals(8L, r.get("quantity"));
        assertEquals("10.0.0.5", f.get("client"), "OPEN_FILE is a master's request even though no list of ours names it");
    }

    // ---------------------------------------------------------------- S7, ENIP, CIP

    private static final String S = "\"uid\":\"Cs\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":40000,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":102,";
    private static final String S_REQ = "\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":102,";
    private static final String S_RSP = "\"is_orig\":false,\"source_h\":\"10.0.0.9\",\"source_p\":102,\"destination_h\":\"10.0.0.5\",\"destination_p\":40000,";

    @Test
    void s7JobsGetTheAcknowledgementsErrorClassAsStatus() throws Exception {
        String rows = "{" + S + S_REQ + "\"rosctr_name\":\"Job-Request\",\"pdu_reference\":1,\"function_code\":\"0x04\",\"function_name\":\"Read Var\"}\n"
                + "{" + S + S_RSP + "\"rosctr_name\":\"ACK-Data\",\"pdu_reference\":1,\"function_code\":\"0x04\",\"function_name\":\"Read Var\",\"error_class\":\"No error\",\"error_code\":\"0x00\"}\n"
                + "{" + S + S_REQ + "\"rosctr_name\":\"Job-Request\",\"pdu_reference\":2,\"function_code\":\"0x05\",\"function_name\":\"Write Var\"}\n"
                + "{" + S + S_RSP + "\"rosctr_name\":\"ACK-Data\",\"pdu_reference\":2,\"function_code\":\"0x05\",\"function_name\":\"Write Var\",\"error_class\":\"Access error\",\"error_code\":\"0x05\"}\n"
                + "{" + S + S_REQ + "\"rosctr_name\":\"Job-Request\",\"pdu_reference\":3,\"function_code\":\"0x29\",\"function_name\":\"PLC Stop\"}\n";
        String szl = "{" + S + S_REQ + "\"pdu_reference\":4,\"method\":\"Request\",\"szl_id\":\"0x0011\",\"szl_id_name\":\"Module identification\"}\n"
                + "{" + S + S_RSP + "\"pdu_reference\":4,\"method\":\"Response\",\"szl_id\":\"0x0011\",\"szl_id_name\":\"Module identification\",\"return_code_name\":\"Success\"}\n";
        String transfer = "{" + S + S_REQ + "\"rosctr\":1,\"pdu_reference\":5,\"function_code\":\"0x1a\",\"block_type\":\"OB\",\"block_number\":\"1\"}\n";
        var f = flow(read(Map.of("s7comm.log", rows, "s7comm_read_szl.log", szl, "s7comm_upload_download.log", transfer)), "s7comm");
        assertEquals("10.0.0.5", f.get("client"));
        assertEquals("102/tcp", f.get("port"));
        assertEquals(Map.of("ok", 1L), op(f, "Read Var").get("statuses"));
        assertEquals("read", op(f, "Read Var").get("access"));
        assertEquals(Map.of("status: access error 0x05", 1L), op(f, "Write Var").get("statuses"));
        assertEquals("control", op(f, "PLC Stop").get("access"));
        var z = op(f, "Read SZL");
        assertEquals("Module identification", z.get("object"));
        assertEquals(17L, z.get("address"), "SZL id 0x0011");
        assertEquals(Map.of("ok", 1L), z.get("statuses"));
        var t = op(f, "Request Download");
        assertEquals("write", t.get("access"), "a download changes the PLC program");
        assertEquals("OB 1", t.get("object"));
        assertTrue(labels(f).containsKey("S7 Read Var") && labels(f).containsKey("S7 PLC Stop"), labels(f).toString());
    }

    @Test
    void enipCommandsAndCipServicesWithPathAndStatus() throws Exception {
        String e = "\"uid\":\"Ce\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":40000,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":44818,";
        String req = "\"is_orig\":true,\"source_h\":\"10.0.0.5\",\"source_p\":40000,\"destination_h\":\"10.0.0.9\",\"destination_p\":44818,";
        String rsp = "\"is_orig\":false,\"source_h\":\"10.0.0.9\",\"source_p\":44818,\"destination_h\":\"10.0.0.5\",\"destination_p\":40000,";
        String enip = "{" + e + req + "\"enip_command\":\"Register Session\",\"enip_status\":\"Success\",\"sender_context\":\"0x0000000000000001\"}\n"
                + "{" + e + rsp + "\"enip_command\":\"Register Session\",\"enip_status\":\"Success\",\"sender_context\":\"0x0000000000000001\"}\n"
                + "{" + e + req + "\"enip_command\":\"Send RR Data\",\"enip_status\":\"Success\",\"sender_context\":\"0x0000000000000002\"}\n"
                + "{" + e + rsp + "\"enip_command\":\"Send RR Data\",\"enip_status\":\"Invalid Session Handle\",\"sender_context\":\"0x0000000000000002\"}\n";
        String cip = "{" + e + req + "\"cip_sequence_count\":7,\"direction\":\"request\",\"cip_service\":\"Get_Attribute_Single\",\"class_id\":1,\"class_name\":\"Identity\",\"instance_id\":1,\"attribute_id\":7}\n"
                + "{" + e + rsp + "\"cip_sequence_count\":7,\"direction\":\"response\",\"cip_service\":\"Get_Attribute_Single\",\"cip_status\":\"Success\"}\n"
                + "{" + e + req + "\"cip_sequence_count\":8,\"direction\":\"request\",\"cip_service\":\"Set_Attribute_Single\",\"class_name\":\"Assembly\",\"instance_id\":100,\"attribute_id\":3}\n"
                + "{" + e + rsp + "\"cip_sequence_count\":8,\"direction\":\"response\",\"cip_service\":\"Set_Attribute_Single\",\"cip_status\":\"Privilege violation\",\"cip_extended_status\":\"Insufficient privilege\"}\n";
        var f = flow(read(Map.of("enip.log", enip, "cip.log", cip)), "ethernet-ip");
        assertEquals("10.0.0.5", f.get("client"));
        assertEquals(Map.of("ok", 1L), op(f, "Register Session").get("statuses"));
        assertEquals(Map.of("status: invalid session handle", 1L), op(f, "Send RR Data").get("statuses"));
        var get = op(f, "Get_Attribute_Single");
        assertEquals("Identity attr 7", get.get("object"));
        assertEquals(1L, get.get("address"));
        assertEquals("read", get.get("access"));
        var set = op(f, "Set_Attribute_Single");
        assertEquals("write", set.get("access"));
        assertEquals("Assembly attr 3", set.get("object"));
        assertEquals(Map.of("status: privilege violation: insufficient privilege", 1L), set.get("statuses"));
        assertTrue(labels(f).containsKey("CIP Set_Attribute_Single") && labels(f).containsKey("EtherNet/IP Register Session"), labels(f).toString());
    }

    @Test
    void cipIoIsUdpFromConnLogAndKeepsNoProcessData() throws Exception {
        String conn = "{\"ts\":1700000000.5,\"uid\":\"Cu\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":2222,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":2222,\"proto\":\"udp\","
                + "\"duration\":1.0,\"orig_bytes\":100,\"resp_bytes\":100,\"conn_state\":\"SF\",\"orig_pkts\":3,\"resp_pkts\":3}\n";
        String io = "{\"uid\":\"Cu\",\"id.orig_h\":\"10.0.0.5\",\"id.orig_p\":2222,\"id.resp_h\":\"10.0.0.9\",\"id.resp_p\":2222,\"connection_id\":99,\"sequence_number\":1,\"data_length\":16,\"io_data\":\"deadbeef\"}\n";
        var f = flow(read(Map.of("conn.log", conn, "cip_io.log", io.repeat(3))), "ethernet-ip");
        assertEquals("2222/udp", f.get("port"));
        assertEquals("udp", f.get("transport"));
        var o = op(f, "CIP I/O data");
        assertEquals(3L, o.get("count"));
        assertEquals(16L, o.get("quantity"));
        assertNull(o.get("sampleValues"), "cyclic process data is not recorded");
    }

    // ---------------------------------------------------------------- port-inferred fallbacks

    private static String conn(String orig, String resp, int port, String service) {
        return "{\"ts\":1700000000.5,\"uid\":\"Cx" + port + "\",\"id.orig_h\":\"" + orig + "\",\"id.orig_p\":40000,\"id.resp_h\":\"" + resp + "\",\"id.resp_p\":" + port
                + ",\"proto\":\"tcp\"," + (service == null ? "" : "\"service\":\"" + service + "\",")
                + "\"duration\":1.0,\"orig_bytes\":100,\"resp_bytes\":100,\"conn_state\":\"SF\",\"orig_pkts\":3,\"resp_pkts\":3}\n";
    }

    @Test
    void aHostThatOnlyHasConnLogOnAnIndustrialPortIsPortInferredNotBareUnknown() throws Exception {
        String conn = conn("10.0.0.5", "10.0.0.9", 502, null) + conn("10.0.0.5", "10.0.0.10", 20000, null) + conn("10.0.0.5", "10.0.0.11", 9999, null)
                + conn("10.0.0.5", "10.0.0.12", 4840, null) + conn("10.0.0.5", "10.0.0.13", 102, "cotp");
        ZeekData d = read(Map.of("conn.log", conn));
        DeviceObservation mb = d.observations().stream().filter(o -> "10.0.0.9".equals(o.ip().get().value())).findFirst().orElseThrow();
        assertEquals(DetectionBasis.ZEEK_PORT, mb.detectionBasis());
        assertEquals(com.pcap.protocol.ProtocolType.MODBUS, mb.protocol());
        assertEquals("502/tcp", mb.service().orElseThrow());
        assertTrue(mb.note().contains("port-inferred"), mb.note());
        assertEquals(com.pcap.protocol.ProtocolType.DNP3, d.observations().stream().filter(o -> "10.0.0.10".equals(o.ip().get().value())).findFirst().orElseThrow().protocol());
        DeviceObservation other = d.observations().stream().filter(o -> "10.0.0.11".equals(o.ip().get().value())).findFirst().orElseThrow();
        assertEquals(DetectionBasis.ZEEK_CONN, other.detectionBasis(), "9999 means nothing");
        assertEquals("unknown", other.protocolName().orElseThrow());
        assertEquals("opc-ua", d.observations().stream().filter(o -> "10.0.0.12".equals(o.ip().get().value())).findFirst().orElseThrow().protocolName().orElseThrow());
        // a service Zeek did name is never overridden by the port
        DeviceObservation s7 = d.observations().stream().filter(o -> "10.0.0.13".equals(o.ip().get().value())).findFirst().orElseThrow();
        assertEquals(DetectionBasis.ZEEK_CONN, s7.detectionBasis());
    }

    @Test
    void anUnidentifiedFlowOnAnIndustrialPortKeepsProtocolUnknownAndAddsAHint() throws Exception {
        ZeekData d = read(Map.of("conn.log", conn("10.0.0.5", "10.0.0.9", 502, null) + conn("10.0.0.5", "10.0.0.9", 9999, null)));
        var flows = d.flows().toList();
        var mb = flows.stream().filter(f -> "502/tcp".equals(f.get("port"))).findFirst().orElseThrow();
        assertEquals("unknown", mb.get("protocol"), "the port does not make it Modbus");
        assertEquals("modbus", mb.get("portHint"));
        assertNull(flows.stream().filter(f -> "9999/tcp".equals(f.get("port"))).findFirst().orElseThrow().get("portHint"));
    }
}
