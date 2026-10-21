package com.pcap.zeek;

import com.pcap.inventory.FlowTable;
import com.pcap.model.DeviceObservation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** What the log reader took from one directory of Zeek logs: flows, host/identity observations and the counts to prove it. */
public record ZeekData(FlowTable flows, List<DeviceObservation> observations, Stats stats) {

    /** Per-log row counts plus the scan and cap bookkeeping, written to {@code source.zeek} of the ingest JSON. */
    public static final class Stats {
        private final Map<String, long[]> logs = new TreeMap<>();   // name -> {rows used, rows skipped}
        long connections, scanAttempts, scanAttemptsUncounted, flowsDroppedOverCap, hosts, hostsDroppedOverCap;
        long observationsDroppedOverCap;

        void used(String log) {
            logs.computeIfAbsent(log, k -> new long[2])[0]++;
        }

        void skipped(String log) {
            logs.computeIfAbsent(log, k -> new long[2])[1]++;
        }

        void present(String log) {
            logs.computeIfAbsent(log, k -> new long[2]);
        }

        public long scanAttempts() {
            return scanAttempts;
        }

        public long connections() {
            return connections;
        }

        public long rowsUsed(String log) {
            long[] c = logs.get(log);
            return c == null ? 0 : c[0];
        }

        public long rowsSkipped(String log) {
            long[] c = logs.get(log);
            return c == null ? 0 : c[1];
        }

        public long totalSkipped() {
            return logs.values().stream().mapToLong(c -> c[1]).sum();
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            Map<String, Object> l = new LinkedHashMap<>();
            logs.forEach((k, c) -> l.put(k, Map.of("rows", c[0], "skipped", c[1])));
            m.put("logs", l);
            m.put("connections", connections);
            m.put("scanAttempts", scanAttempts);
            m.put("hosts", hosts);
            if (scanAttemptsUncounted > 0) {
                m.put("scanAttemptsUncounted", scanAttemptsUncounted);
            }
            if (flowsDroppedOverCap > 0) {
                m.put("flowsDroppedOverCap", flowsDroppedOverCap);
            }
            if (hostsDroppedOverCap > 0) {
                m.put("hostsDroppedOverCap", hostsDroppedOverCap);
            }
            if (observationsDroppedOverCap > 0) {
                m.put("observationsDroppedOverCap", observationsDroppedOverCap);
            }
            return m;
        }
    }
}
