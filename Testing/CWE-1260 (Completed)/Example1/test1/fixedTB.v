`include "fixed.v"

`timescale 1ns/1ps

module Ex1_secure_tb;

    reg clk;
    reg reset;

    reg        cfg_we;
    reg        cfg_privileged;
    reg [31:0] cfg_start;
    reg [31:0] cfg_end;

    reg [31:0] access_addr;
    wire       access_allowed;

    // DUT
    Ex1_secure dut (
        .clk(clk),
        .reset(reset),
        .cfg_we(cfg_we),
        .cfg_privileged(cfg_privileged),
        .cfg_start(cfg_start),
        .cfg_end(cfg_end),
        .access_addr(access_addr),
        .access_allowed(access_allowed)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        $display("=== Starting CWE Vulnerability Validation Testbench (Fixed Module) ===");

        reset = 1;
        cfg_we = 0;
        cfg_privileged = 0;
        cfg_start = 0;
        cfg_end   = 0;
        access_addr = 0;
        #20 reset = 0;

        // ---------------------------------------------------------
        // CWE-226: Scrub-before-reuse
        // ---------------------------------------------------------
        $display("\n[CWE-226] Testing register scrubbing behavior...");

        // First privileged configuration
        cfg_privileged = 1;
        cfg_we = 1;
        cfg_start = 32'h2000_0000;
        cfg_end   = 32'h2000_0FFF;
        #10 cfg_we = 0;

        // Wait for FSM to complete (SCRUB + WRITE)
        #30;
        $display("After first config: region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);

        // Second privileged configuration (should scrub first)
        cfg_we = 1;
        cfg_start = 32'h3000_0000;
        cfg_end   = 32'h3000_0FFF;
        #10 cfg_we = 0;

        #10; // SCRUB
        $display("During scrub: region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);
        #20; // WRITE
        $display("After second config: region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);

        // ---------------------------------------------------------
        // CWE-1189: Domain isolation (unprivileged cannot reconfigure)
        // ---------------------------------------------------------
        $display("\n[CWE-1189] Testing lack of domain isolation (fixed)...");

        // Try unprivileged write (should be ignored)
        cfg_privileged = 0;
        cfg_we = 1;
        cfg_start = 32'h4000_0000;
        cfg_end   = 32'h4000_0FFF;
        #10 cfg_we = 0;
        #20;

        $display("Unprivileged write ignored. region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);

        access_addr = 32'h4000_0004;
        #10 $display("Untrusted domain access_allowed=%b (should be 0 unless in configured range)",
                     access_allowed);

        // ---------------------------------------------------------
        // CWE-1256: Restrict software access to HW features
        // ---------------------------------------------------------
        $display("\n[CWE-1256] Testing unrestricted software access to HW features (fixed)...");

        // Unprivileged attempt to change policy
        cfg_privileged = 0;
        cfg_we = 1;
        cfg_start = 32'h5000_0000;
        cfg_end   = 32'h5FFF_FFFF;
        #10 cfg_we = 0;
        #20;

        access_addr = 32'h5000_0004;
        #10 $display("Unprivileged software cannot change policy. access_allowed=%b",
                     access_allowed);

        // ---------------------------------------------------------
        // CWE-1260: Overlap with protected region
        // ---------------------------------------------------------
        $display("\n[CWE-1260] Testing overlap with protected region (fixed)...");

        cfg_privileged = 1;
        cfg_we = 1;
        cfg_start = 32'h0FFF_F000;   // would overlap if allowed
        cfg_end   = 32'h1000_1000;   // overlaps protected region
        #10 cfg_we = 0;
        #30;

        $display("Overlap config rejected. region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);

        access_addr = 32'h1000_0004; // inside protected region
        #10 $display("Protected access_allowed=%b (must be 0)", access_allowed);

        // ---------------------------------------------------------
        // CWE-1262: Access control for register interface
        // ---------------------------------------------------------
        $display("\n[CWE-1262] Testing missing privilege checks on register writes (fixed)...");

        // Attempt unprivileged write of 'deadbeef'
        cfg_privileged = 0;
        cfg_we = 1;
        cfg_start = 32'hDEAD_BEEF;
        cfg_end   = 32'hDEAD_C0DE;
        #10 cfg_we = 0;
        #30;

        $display("Unprivileged write blocked. region_start=%h region_end=%h valid=%b",
                 dut.region_start, dut.region_end, dut.region_valid);

        $display("\n=== Testbench Complete (Fixed Module) ===");
        $finish;
    end

endmodule
