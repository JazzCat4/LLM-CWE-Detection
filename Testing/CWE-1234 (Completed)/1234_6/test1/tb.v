`include "1234_6.v"

`timescale 1ns/1ps

module tb_test;

    reg         clk;
    reg         rst_n;
    reg         wr_req;
    reg  [15:0] din;
    reg         lock_flag;
    reg         scan_mode;
    wire [15:0] dout;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .wr_req(wr_req),
        .din(din),
        .lock_flag(lock_flag),
        .scan_mode(scan_mode),
        .dout(dout)
    );

    // Clock
    always #5 clk = ~clk;

    // Task: print state
    task show;
        $display("[%0t] rst=%b lock_flag=%b lock_status=%b wr_req=%b scan=%b din=%h dout=%h",
                 $time, rst_n, lock_flag, dut.lock_status, wr_req, scan_mode, din, dout);
    endtask

    initial begin
        clk = 0;
        rst_n = 0;
        wr_req = 0;
        din = 16'h0000;
        lock_flag = 0;
        scan_mode = 0;

        // ============================================================
        // CWE‑226: Sensitive data not scrubbed before reuse
        // ============================================================
        $display("\n=== CWE‑226 TEST: Sensitive data persists across contexts ===");

        // Write sensitive value
        #10 rst_n = 1;
        #10 wr_req = 1; din = 16'hBEEF; show;

        // Lock the register
        #10 lock_flag = 1; wr_req = 0; show;

        // Enter scan/debug mode (new context)
        #10 scan_mode = 1; wr_req = 1; din = 16'h1234; show;

        // Check if old sensitive value was scrubbed (it should have been)
        #10 show;

        // ============================================================
        // CWE‑1262: Improper access control for register interface
        // ============================================================
        $display("\n=== CWE‑1262 TEST: Write allowed without privilege ===");

        // Reset and lock
        #10 rst_n = 0;
        #10 rst_n = 1; lock_flag = 1; wr_req = 0; scan_mode = 0; show;

        // Attempt write while locked (should NOT be allowed)
        #10 wr_req = 1; din = 16'hAAAA; show;

        // If dout changed → lock not enforced
        #10 show;

        // ============================================================
        // CWE‑1256: Unprivileged software can access hardware features
        // ============================================================
        $display("\n=== CWE‑1256 TEST: Unprivileged write to protected register ===");

        // Assume wr_req is unprivileged
        #10 wr_req = 1; din = 16'hFACE; show;

        // If dout changes → unprivileged write succeeded
        #10 show;

        // ============================================================
        // CWE‑1247: Glitch attack bypassing lock
        // ============================================================
        $display("\n=== CWE‑1247 TEST: Clock glitch bypassing security check ===");

        // Lock the register
        #10 lock_flag = 1; wr_req = 0; scan_mode = 0; show;

        // Inject a clock glitch (short pulse)
        #2 clk = ~clk;  // glitch
        #2 clk = ~clk;  // glitch

        // Attempt write during glitch window
        #10 wr_req = 1; din = 16'hDEAD; show;

        // If dout changed → glitch bypassed lock
        #10 show;

        // ============================================================
        // CWE‑1234: Debug/scan mode overrides lock bit
        // ============================================================
        $display("\n=== CWE‑1234 TEST: Debug mode bypasses lock ===");

        // Lock the register
        #10 rst_n = 0;
        #10 rst_n = 1; lock_flag = 1; wr_req = 0; scan_mode = 0; show;

        // Attempt write while locked (should fail)
        #10 wr_req = 1; din = 16'hC0DE; show;

        // Now assert scan_mode (debug override)
        #10 scan_mode = 1; wr_req = 1; din = 16'hC0DE; show;

        // If dout changed → debug override bypassed lock
        #10 show;

        $display("\n=== TEST COMPLETE ===");
        #20 $finish;
    end

endmodule
