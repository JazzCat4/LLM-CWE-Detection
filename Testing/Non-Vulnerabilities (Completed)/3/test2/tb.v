`include "3.v"

`timescale 1ns/1ps

module tb_test;

    reg  [2:0] usr_id;
    reg  [7:0] data_in;
    reg        clk;
    reg        rst_n;
    wire [7:0] data_out;

    // DUT
    test dut (
        .data_out(data_out),
        .usr_id(usr_id),
        .data_in(data_in),
        .clk(clk),
        .rst_n(rst_n)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal
    end

    // Main stimulus
    initial begin
        $display("=== Starting CWE Security Validation Testbench ===");

        // ------------------------------------------------------------
        // CWE‑226: Sensitive data not scrubbed between privilege changes
        // ------------------------------------------------------------
        $display("\n[CWE‑226] Testing lack of scrubbing between contexts");

        rst_n = 0; usr_id = 0; data_in = 0;
        #12 rst_n = 1;

        // Privileged user writes sensitive data
        usr_id = 3'h4;
        data_in = 8'hA5;
        #10;

        // Switch to unprivileged user — data_out should be scrubbed (but is NOT)
        usr_id = 3'h1;
        #10;

        if (data_out == 8'hA5)
            $display("VULN‑226: Sensitive data persists across privilege change (data_out=%h)", data_out);

        // ------------------------------------------------------------
        // CWE‑1262: Improper access control for register interface
        // ------------------------------------------------------------
        $display("\n[CWE‑1262] Testing improper access control");

        // Unprivileged user attempts write — should be denied
        usr_id = 3'h0;
        data_in = 8'h3C;
        #10;

        if (data_out == 8'h3C)
            $display("VULN‑1262: Unprivileged write succeeded!");

        // Privilege signal is software‑controlled — attacker sets usr_id=4
        usr_id = 3'h4;
        data_in = 8'hF0;
        #10;

        if (data_out == 8'hF0)
            $display("VULN‑1262: Privilege bit fully software‑controlled (grant_access bypass)");

        // ------------------------------------------------------------
        // CWE‑1256: Unprivileged access to hardware‑controlled features
        // ------------------------------------------------------------
        $display("\n[CWE‑1256] Testing improper restriction of hardware features");

        // Attacker toggles usr_id to privileged value
        usr_id = 3'h4;
        data_in = 8'h55;
        #10;

        if (data_out == 8'h55)
            $display("VULN‑1256: Unprivileged software can escalate privilege by writing usr_id");

        // ------------------------------------------------------------
        // CWE‑1247: Glitch susceptibility
        // ------------------------------------------------------------
        $display("\n[CWE‑1247] Testing glitch susceptibility");

        // Inject a clock glitch (short pulse)
        usr_id = 3'h0;
        data_in = 8'h99;

        #7 clk = 1; #1 clk = 0;  // glitch pulse

        // Now attacker sets privileged ID immediately after glitch
        usr_id = 3'h4;
        #10;

        if (data_out == 8'h99)
            $display("VULN‑1247: Clock glitch allowed bypass of privilege check");

        // ------------------------------------------------------------
        // CWE‑1234: Debug/test override (module has no debug signals)
        // ------------------------------------------------------------
        $display("\n[CWE‑1234] Testing debug override vulnerabilities");

        // No debug/test/JTAG signals exist — confirm no alternate path
        // This test simply documents absence of protection mechanisms
        $display("INFO‑1234: No debug/test paths present; cannot validate lock override protections.");

        $display("\n=== Security Validation Complete ===");
        $finish;
    end

endmodule
