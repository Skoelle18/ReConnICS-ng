package com.pcap.inventory;

import com.pcap.model.DetectionBasis;
import com.pcap.model.DeviceObservation;
import com.pcap.model.IdentityField;
import com.pcap.protocol.ProtocolDetector;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class DeviceAggregator {
    private final DeviceMatcher matcher = new DeviceMatcher();
    private final IdentityResolver resolver = new IdentityResolver();
    private int observationCount;
    private int identityFieldCount;
    private int portOnlyCount;
    private int headerValidatedCount;
    private int messageDecodedCount;

    public void accept(DeviceObservation obs) {
        if (obs == null) {
            return;
        }
        observationCount++;
        switch (obs.detectionBasis()) {
            case PORT_HEURISTIC -> portOnlyCount++;
            case HEADER_VALIDATED -> headerValidatedCount++;
            case MESSAGE_DECODED -> messageDecodedCount++;
        }
        CandidateDevice device = matcher.match(obs);
        obs.ip().ifPresent(device::observeIp);
        if (obs.detectionBasis() != DetectionBasis.PORT_HEURISTIC) {
            device.observeRole(obs.role());
        }
        // Sub-devices record the carrier MAC only so a lone Modbus unit can be folded back into its IP;
        // DeviceMatcher.finalizeMacs() never emits a MAC on a sub-device.
        obs.mac().ifPresent(m -> device.observeMac(m, obs.frameNumber()));
        if (ProtocolDetector.ARP_ROLE.equals(obs.role())) {
            obs.mac().ifPresent(device::markOwnMac);
        }
        device.observeProtocol(obs.protocol(), obs.detectionBasis(), obs.frameNumber());
        for (IdentityField f : obs.identityFields()) {
            device.addField(f);
            identityFieldCount++;
        }
    }

    public List<ResolvedAsset> resolveAssets() {
        matcher.finalizeMacs();
        List<CandidateDevice> candidates = matcher.candidates();
        candidates.sort(Comparator
                .comparing((CandidateDevice d) -> d.primaryIp().orElse("~"))
                .thenComparing(d -> d.primaryMac().orElse("~"))
                .thenComparing(CandidateDevice::captureScopedId));
        List<ResolvedAsset> assets = new ArrayList<>();
        for (CandidateDevice c : candidates) {
            // Keep port-only candidates only if they have no stronger sibling? Keep all for inventory.
            IdentityResolver.ResolvedIdentity id = resolver.resolve(c);
            assets.add(new ResolvedAsset(c, id));
        }
        return assets;
    }

    public int observationCount() {
        return observationCount;
    }

    public int identityFieldCount() {
        return identityFieldCount;
    }

    public int portOnlyCount() {
        return portOnlyCount;
    }

    public int headerValidatedCount() {
        return headerValidatedCount;
    }

    public int messageDecodedCount() {
        return messageDecodedCount;
    }

    public int candidateCount() {
        return matcher.candidates().size();
    }

    public record ResolvedAsset(CandidateDevice device, IdentityResolver.ResolvedIdentity identity) {
        public boolean hasStrongProtocolEvidence() {
            return device.detectionBases().contains(DetectionBasis.HEADER_VALIDATED)
                    || device.detectionBases().contains(DetectionBasis.MESSAGE_DECODED)
                    || device.hasDecodedIdentity();
        }
    }
}
