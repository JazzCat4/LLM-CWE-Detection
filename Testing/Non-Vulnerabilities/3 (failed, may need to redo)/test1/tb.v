`include "3.v"

`timescale 1ns/1ps

module tb_test_security;

    reg  clk;
    reg  rst_n;
    reg  [2:0] usr_id;
    reg  [7:0] data_in;
    wire [7:0] data_out;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .usr_id(usr_id),
        .data_in(data_in),
        .data_out(data_out)
    );

    // Normal clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal
    end

    // Task: Inject a clock glitch (CWE‑1247)
    task inject_clock_glitch;
        begin
            #1 clk = ~clk;   // very short pulse
            #1 clk = ~clk;
        end
    endtask

    // Task: Pulse reset asynchronously (CWE‑1247)
    task glitch_reset;
        begin
            rst_n = 0;
            #1 rst_n = 1;
        end
    endtask

    initial begin
        $display("=== Security Testbench Start ===");

        // Initial conditions
        rst_n   = 0;
        usr_id  = 0;
        data_in = 8'hAA;

        // Release reset
        #20 rst_n = 1;

        // ------------------------------------------------------------
        // Test 1: Verify normal privileged write
        // ------------------------------------------------------------
        $display("[T1] Normal privileged write");
        usr_id  = 3'h4;     // privileged
        data_in = 8'h55;
        #10;
        $display("data_out = %h (expected 55)", data_out);

        // ------------------------------------------------------------
        // Test 2: Verify normal unprivileged write is blocked
        // ------------------------------------------------------------
        $display("[T2] Normal unprivileged write");
        usr_id  = 3'h2;     // unprivileged
        data_in = 8'h99;
        #10;
        $display("data_out = %h (expected 55)", data_out);

        // ------------------------------------------------------------
        // Test 3: CWE‑1247 — Clock glitch bypassing access check
        // ------------------------------------------------------------
        $display("[T3] Injecting clock glitch to bypass privilege check");
        usr_id  = 3'h2;     // attacker is unprivileged
        data_in = 8'hF0;    // attacker payload

        // Inject glitch exactly during access check
        #3 inject_clock_glitch;

        #10;
        $display("data_out = %h (if F0, glitch bypassed access!)", data_out);

        // ------------------------------------------------------------
        // Test 4: CWE‑1247 — Reset glitch corrupting security state
        // ------------------------------------------------------------
        $display("[T4] Reset glitch attack");
        usr_id  = 3'h4;
        data_in = 8'hA5;
        #10;

        glitch_reset;   // asynchronous reset pulse

        #10;
        $display("data_out = %h (should be 00 after reset glitch)", data_out);

        // ------------------------------------------------------------
        // Test 5: CWE‑1234 — Debug override simulation
        // (Your module has no debug signals, so we emulate a debug path
        // by forcing internal signals.)
        // ------------------------------------------------------------
        $display("[T5] Simulated debug override attack");

        // Force internal grant_access (simulating a debug shadow path)
        force dut.grant_access = 1'b1;
        data_in = 8'hDE;

        #10;
        $display("data_out = %h (if DE, debug override bypassed lock!)", data_out);

        release dut.grant_access;

        $display("=== Security Testbench Complete ===");
        #20 $finish;
    end

endmodule
