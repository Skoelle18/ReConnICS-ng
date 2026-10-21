package com.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Not a test: a timing harness for Site.inventory(), skipped unless -Dbench.index is set. Run:
 * <pre>mvn -o test -Dtest=SiteInventoryBench -Dbench.index=data/index.json [-Dbench.assets=171] [-Dbench.reps=20]</pre>
 * It posts N assets built from real index rows (so each one matches), then times the calls the UI makes: the 1.5 s
 * poll (GET /inventory + /captures + /index = one inventory() each) and one more merge.
 */
class SiteInventoryBench {
    @TempDir Path tmp;

    @Test
    void time() throws Exception {
        String idx = System.getProperty("bench.index");
        assumeTrue(idx != null, "set -Dbench.index to run");
        int n = Integer.getInteger("bench.assets", 171), reps = Integer.getInteger("bench.reps", 20);
        AdvisoryIndex index = AdvisoryIndex.load(Path.of(idx), null, true);
        Site site = new Site(tmp.resolve("site"), index, Path.of(idx), null, true);

        long ts = System.nanoTime();
        var clean = Inventory.sanitize(index);
        long tm = System.nanoTime();
        new AdvisoryMatcher(clean);
        System.out.printf("BENCH sanitize=%.0fms matcherCtor=%.0fms%n", (tm - ts) / 1e6, (System.nanoTime() - tm) / 1e6);

        List<Object> assets = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            var r = index.rows.get((i * 97) % index.rows.size());
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("ip", "10." + (i / 250) + "." + (i % 250 + 1) + ".10");
            a.put("vendor", r.vendor());
            a.put("model", r.product());
            a.put("firmware", "1." + i);
            assets.add(a);
        }
        long t0 = System.nanoTime();
        site.addPosted(assets, "bench");                                 // one merge: calls inventory() before and after
        double merge = (System.nanoTime() - t0) / 1e6;

        site.inventory();                                                // warm-up
        long t1 = System.nanoTime();
        for (int i = 0; i < reps; i++) site.inventory();
        double per = (System.nanoTime() - t1) / 1e6 / reps;

        List<Object> more = new ArrayList<>(assets.subList(0, 1));
        ((Map<String, Object>) more.get(0)).put("ip", "10.200.0.1");
        long t2 = System.nanoTime();
        site.addPosted(more, "bench");
        double merge2 = (System.nanoTime() - t2) / 1e6;

        System.out.printf("BENCH assets=%d indexRows=%d firstMerge=%.0fms inventory()=%.1fms/call (avg of %d) secondMerge=%.0fms%n",
                n, index.rows.size(), merge, per, reps, merge2);
    }
}
