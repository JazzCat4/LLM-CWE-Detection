`include "Example1.v"

`timescale 1ns/1ps

module Ex1_tb;

    reg clk;
    reg reset;

    reg cfg_we;
    reg [31:0] cfg_start;
    reg [31:0] cfg_end;

    reg [31:0] access_addr;
    wire access_allowed;

    // Instantiate DUT
    Ex1 dut (
        .clk(clk),
        .reset(reset),
        .cfg_we(cfg_we),
        .cfg_start(cfg_start),
        .cfg_end(cfg_end),
        .access_addr(access_addr),
        .access_allowed(access_allowed)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Test stimulus
    initial begin
        $display("=== Starting CWE Vulnerability Validation Testbench ===");

        // ---------------------------------------------------------
        // CWE‑226: Sensitive Information Not Removed Before Reuse
        // ---------------------------------------------------------
        $display("\n[CWE‑226] Testing register scrubbing behavior...");

        reset = 1; cfg_we = 0; cfg_start = 0; cfg_end = 0;
        #20 reset = 0;

        // Write a region
        cfg_we = 1;
        cfg_start = 32'h2000_0000;
        cfg_end   = 32'h2000_0FFF;
        #10 cfg_we = 0;

        // Reconfigure without scrubbing
        cfg_we = 1;
        cfg_start = 32'h3000_0000;
        cfg_end   = 32'h3000_0FFF;
        #10 cfg_we = 0;

        $display("Region reused without zero‑scrub. region_start=%h region_end=%h",
                 dut.region_start, dut.region_end);

        // ---------------------------------------------------------
        // CWE‑1189: Improper Isolation of Shared Resources
        // ---------------------------------------------------------
        $display("\n[CWE‑1189] Testing lack of domain isolation...");

        // Simulate untrusted agent writing configuration
        cfg_we = 1;
        cfg_start = 32'h2000_0000;
        cfg_end   = 32'h2000_0FFF;
        #10 cfg_we = 0;

        // Access from another domain
        access_addr = 32'h2000_0004;
        #10 $display("Untrusted domain access allowed=%b", access_allowed);

        // ---------------------------------------------------------
        // CWE‑1256: Improper Restriction of Software Interfaces
        // ---------------------------------------------------------
        $display("\n[CWE‑1256] Testing unrestricted software access to HW features...");

        // Unprivileged software reprograms access control
        cfg_we = 1;
        cfg_start = 32'h4000_0000;
        cfg_end   = 32'h4FFF_FFFF;
        #10 cfg_we = 0;

        access_addr = 32'h4000_0004;
        #10 $display("Unprivileged software changed access policy. access_allowed=%b",
                     access_allowed);

        // ---------------------------------------------------------
        // CWE‑1260: Overlap Between Protected Memory Ranges
        // ---------------------------------------------------------
        $display("\n[CWE‑1260] Testing overlap with protected region...");

        // Protected region is 0x1000_0000 – 0x1000_FFFF
        // Try to overlap by setting start just below protected region
        cfg_we = 1;
        cfg_start = 32'h0FFF_F000;   // allowed
        cfg_end   = 32'h1000_1000;   // overlaps protected region!
        #10 cfg_we = 0;

        access_addr = 32'h1000_0004; // inside protected region
        #10 $display("Overlap test: access_allowed=%b (should be denied)", access_allowed);

        // ---------------------------------------------------------
        // CWE‑1262: Improper Access Control for Register Interface
        // ---------------------------------------------------------
        $display("\n[CWE‑1262] Testing missing privilege checks on register writes...");

        // Any agent can write configuration
        cfg_we = 1;
        cfg_start = 32'hDEAD_BEEF;
        cfg_end   = 32'hDEAD_C0DE;
        #10 cfg_we = 0;

        $display("Write accepted without privilege check. region_start=%h region_end=%h",
                 dut.region_start, dut.region_end);

        $display("\n=== Testbench Complete ===");
        $finish;
    end

endmodule
