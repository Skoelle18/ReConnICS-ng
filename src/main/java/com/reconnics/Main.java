package com.reconnics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    static final Map<Integer, String> PORTS = Map.of(502,"modbus", 102, "s7comm", 44818, "enip");

    static final class Dev{
        final String ip,role;
        String mac;
        final Set<String> protocols = new LinkedHashSet<>();
        final int firstFrame;
        Dev(String ip, String role, int firstFrame){
            this.ip = ip;
            this.role = role;
            this.firstFrame = firstFrame;
        }
    }
    static final Map<String, Dev> servers = new LinkedHashMap<>();
    static final Map<String, Dev> clients = new LinkedHashMap<>();

    static void main(String[] args) throws IOException {

        if(args.length < 1){
                System.err.println("Usage: java -jar reconnincs-ng.jar <file.pcap>");
                System.exit(2);
        }

        byte[] f = Files.readAllBytes(Path.of(args[0]));
        if (f.length < 24) fail("file too short to be a pcap");

    }

    static void fail(String msg){
        System.err.println("error: "+msg);
        System.exit(1);
    }
}


