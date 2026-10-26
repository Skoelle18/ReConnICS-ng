package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The Site inventory runs the bundled OUI tables (curated ICS list over the IEEE MA-L registry): a MAC-derived vendor, LOW, never a match basis. */
class SiteOuiTest {
    @TempDir Path tmp;

    @Test
    void macOnlyDeviceGetsAMacDerivedVendorThatDoesNotMatch() throws Exception {
        var rows = List.of(new AdvisoryIndex.Row("ICSA-1", "Siemens thing", "Siemens", "SIMATIC S7-1500", null, "all", List.of("CVE-2000-0001"), List.of(), 9.8));
        Site site = new Site(tmp.resolve("site"), new AdvisoryIndex(AdvisoryIndex.newMeta("test", "2026.10.01", 1), rows), tmp.resolve("i.json"), null, true);
        site.addPosted(List.of(Map.of("ip", "10.0.0.5", "mac", "00:1b:1b:aa:bb:cc"), Map.of("ip", "10.0.0.6", "mac", "00:1b:1b:aa:bb:cd", "vendor", "Acme")), "t");
        Inventory inv = site.inventory();
        var r = inv.records.stream().filter(x -> x.id.equals("10.0.0.5")).findFirst().orElseThrow();
        assertEquals("Siemens AG", r.v("vendor_oui"));
        assertEquals(Inventory.Conf.LOW, r.f.get("vendor_oui").conf());
        assertNull(r.v("vendor"), "an OUI is not an identity");
        assertEquals(AdvisoryMatcher.Level.NONE, r.match.level(), "and never feeds the advisory match");
        assertTrue(inv.ouiRun);
    }

    @Test
    void bundledTableHoldsKnownIcsVendors() {
        assertEquals("Rockwell Automation", Site.OUI.get("0000BC"));
        assertEquals("Telemecanique Electrique", Site.OUI.get("0080F4"));
        assertEquals("Phoenix Contact GmbH & Co. KG", Site.OUI.get("00A045"));
        assertEquals("Moxa Technologies Corp., Ltd.", Site.OUI.get("0090E8"));
        assertEquals("WAGO Kontakttechnik GmbH", Site.OUI.get("0030DE"));
        assertEquals("Siemens AG", Site.OUI.get("001B1B"), "the curated ICS name wins over the registry's \"Siemens AG,\"");
        assertEquals("Cisco Systems, Inc", Site.OUI.get("00000C"), "the full MA-L registry is bundled too, so IT hosts get a NIC maker");
        assertTrue(Site.OUI.size() > 30_000, "scripts/update-oui.py refreshes it");
    }
}
