package com.advisory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class AdvisoryCli {
    private static final String USAGE = """
            usage: java -jar target/reconnics-ng.jar <command> [options]

            Online side (has internet):
              keygen      --keys DIR                       Ed25519 keypair for signing the index
              build-index [--feed PATH|URL] [--kev PATH|URL] [--cache DIR] [--out FILE]
                          [--limit N] [--offline] [--sign-key FILE]
                          mirror CSAF OT advisories into --cache, build index (--offline: cache only)

            Offline side (air-gapped analyst laptop):
              match --index FILE [--pubkey FILE] [--format json|csv|html] [--out FILE] ASSETS.json
              serve --index FILE [--pubkey FILE] [--port 8088]     ingest API for the PCAP project
              inventory --in OBSERVATIONS.json --out DIR [--oui oui.csv] [--index FILE [--pubkey FILE]]
            """;

    public static final java.util.Set<String> COMMANDS = java.util.Set.of("keygen", "build-index", "match", "serve", "inventory");

    public static void main(String[] argv) throws Exception {
        if (argv.length == 0) { System.err.print(USAGE); System.exit(2); }
        if (argv[0].equals("inventory")) System.exit(Inventory.run(java.util.Arrays.copyOfRange(argv, 1, argv.length), System.err));
        Map<String, String> o = new HashMap<>();
        List<String> pos = new ArrayList<>();
        for (int i = 1; i < argv.length; i++) {
            if (!argv[i].startsWith("--")) pos.add(argv[i]);
            else if (argv[i].equals("--offline")) o.put("offline", "1");
            else if (i + 1 < argv.length) o.put(argv[i].substring(2), argv[++i]);
            else die("missing value for " + argv[i]);
        }
        switch (argv[0]) {
            case "keygen" -> {
                Path dir = Path.of(o.getOrDefault("keys", "keys"));
                AdvisoryIndex.keygen(dir);
                System.err.println("wrote " + dir.resolve("index-signing.key") + " (keep on online side) and .pub (copy to offline side)");
            }
            case "build-index" -> {
                Path cache = Path.of(o.getOrDefault("cache", "data/csaf"));
                Path out = Path.of(o.getOrDefault("out", "data/index.json"));
                String feed = o.getOrDefault("feed", IndexBuilder.CSAF_FEED);
                if (!o.containsKey("offline")) IndexBuilder.sync(feed, cache, Integer.parseInt(o.getOrDefault("limit", "0")));
                var idx = IndexBuilder.build(cache, o.getOrDefault("kev", IndexBuilder.KEV_FEED), feed);
                if (out.getParent() != null) Files.createDirectories(out.getParent());
                Files.writeString(out, idx.toJson());
                if (o.containsKey("sign-key")) AdvisoryIndex.sign(out, Path.of(o.get("sign-key")));
                System.err.printf("index: %s advisories, %d rows -> %s%n", Json.write(idx.meta.get("advisories")), idx.rows.size(), out);
            }
            case "match" -> {
                if (pos.size() != 1) die("match needs exactly one ASSETS.json");
                var idx = loadIndex(o);
                Object doc = Json.parse(Files.readString(Path.of(pos.get(0))));
                List<Asset> assets = new ArrayList<>();
                for (Object a : doc instanceof List ? Json.arr(doc) : Json.arr(Json.obj(doc).get("assets"))) assets.add(Asset.from(a));
                var r = Report.run(new AdvisoryMatcher(idx), assets);
                String text = switch (o.getOrDefault("format", "json")) {
                    case "csv" -> Report.csv(r);
                    case "html" -> Report.html(r, idx.meta);
                    case "json" -> Json.write(Report.json(r, idx.meta));
                    default -> { die("unknown --format"); yield ""; }
                };
                if (o.containsKey("out")) Files.writeString(Path.of(o.get("out")), text);
                else System.out.println(text);
            }
            case "serve" -> {
                int port = Integer.parseInt(o.getOrDefault("port", "8088"));
                new IngestServer(loadIndex(o)).start(port);
                System.err.println("ingest API on http://127.0.0.1:" + port + "/api/v1/");
            }
            default -> { System.err.print(USAGE); System.exit(2); }
        }
    }

    private static AdvisoryIndex loadIndex(Map<String, String> o) throws Exception {
        if (!o.containsKey("index")) die("--index required");
        return AdvisoryIndex.load(Path.of(o.get("index")), o.containsKey("pubkey") ? Path.of(o.get("pubkey")) : null);
    }

    private static void die(String msg) { System.err.println(msg); System.exit(2); }
}
