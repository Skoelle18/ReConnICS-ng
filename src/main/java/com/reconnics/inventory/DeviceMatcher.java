package com.reconnics.inventory;

import com.reconnics.model.DeviceObservation;
import com.reconnics.util.IpAddress;
import com.reconnics.util.MacAddress;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Conservative matcher: same non-broadcast MAC merges; otherwise same IP merges only when
 * MAC is missing on both sides and no conflicting MAC was previously bound to that IP.
 */
public final class DeviceMatcher {
    private final Map<String, CandidateDevice> byKey = new LinkedHashMap<>();
    private final Map<String, String> ipToMac = new LinkedHashMap<>();
    private int seq;

    public CandidateDevice match(DeviceObservation obs) {
        Optional<MacAddress> mac = obs.mac().filter(m -> !m.isBroadcastOrMulticast());
        Optional<IpAddress> ip = obs.ip();

        if (mac.isPresent()) {
            String macKey = "mac:" + mac.get().value();
            CandidateDevice byMac = byKey.get(macKey);
            if (byMac != null) {
                if (ip.isPresent()) {
                    bindIpMac(ip.get().value(), mac.get().value(), byMac);
                }
                return byMac;
            }
            if (ip.isPresent()) {
                String bound = ipToMac.get(ip.get().value());
                if (bound != null && !bound.equals(mac.get().value())) {
                    // Conflict: IP reused with different MAC — keep separate
                    CandidateDevice d = newDevice("conflict-" + ip.get().value() + "-" + (++seq));
                    d.addMergeNote("IP " + ip.get().value() + " previously seen with MAC " + bound
                            + "; keeping separate from MAC " + mac.get().value());
                    byKey.put(macKey, d);
                    return d;
                }
            }
            CandidateDevice d = newDevice(mac.get().value());
            byKey.put(macKey, d);
            if (ip.isPresent()) {
                bindIpMac(ip.get().value(), mac.get().value(), d);
            }
            return d;
        }

        if (ip.isPresent()) {
            String ipKey = "ip:" + ip.get().value();
            String boundMac = ipToMac.get(ip.get().value());
            if (boundMac != null) {
                CandidateDevice d = byKey.get("mac:" + boundMac);
                if (d != null) {
                    return d;
                }
            }
            CandidateDevice existing = byKey.get(ipKey);
            if (existing != null) {
                return existing;
            }
            CandidateDevice d = newDevice(ip.get().value());
            byKey.put(ipKey, d);
            return d;
        }

        CandidateDevice d = newDevice("unknown-" + (++seq));
        byKey.put("id:" + d.captureScopedId(), d);
        return d;
    }

    private void bindIpMac(String ip, String mac, CandidateDevice device) {
        String prev = ipToMac.putIfAbsent(ip, mac);
        if (prev != null && !prev.equals(mac)) {
            device.addMergeNote("observed IP " + ip + " with MAC " + mac + " after " + prev);
        } else {
            // Also index IP key to same device for later IP-only observations
            byKey.putIfAbsent("ip:" + ip, device);
        }
    }

    private CandidateDevice newDevice(String id) {
        return new CandidateDevice(id);
    }

    public List<CandidateDevice> candidates() {
        // Deduplicate instances (same object may be under mac+ip keys)
        List<CandidateDevice> list = new ArrayList<>();
        for (CandidateDevice d : byKey.values()) {
            if (!list.contains(d)) {
                list.add(d);
            }
        }
        return list;
    }
}
