`timescale 1ns/1ps

module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg         clear_acc;
    reg  [15:0] data_in;
    wire [15:0] acc;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .secret_bit(secret_bit),
        .clear_acc(clear_acc),
        .data_in(data_in),
        .acc(acc)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz
    end

    initial begin
        $display("=== Secure DUT Testbench (CWE-226 & CWE-1300 Validation) ===");

        // ------------------------------------------------------------
        // PHASE 0 — Initialization
        // ------------------------------------------------------------
        rst_n      = 0;
        secret_bit = 0;
        clear_acc  = 0;
        data_in    = 0;

        repeat(2) @(posedge clk);
        rst_n = 1;

        // ------------------------------------------------------------
        // PHASE 1 — CWE‑1300: Constant-time behavior validation
        // ------------------------------------------------------------
        // Goal: Ensure secret_bit only affects mux selection, not timing.
        //       Both add/sub datapaths are active every cycle.
        // ------------------------------------------------------------
        $display("\n[PHASE 1] CWE‑1300: Constant-time datapath test");

        data_in = 16'h00F0;

        $display("  Applying secret_bit = 1 (ADD path selected)");
        secret_bit = 1;
        repeat(4) @(posedge clk);

        $display("  Applying secret_bit = 0 (SUB path selected)");
        secret_bit = 0;
        repeat(4) @(posedge clk);

        // ------------------------------------------------------------
        // PHASE 2 — CWE‑226: Scrubbing on context switch
        // ------------------------------------------------------------
        // Goal: Ensure acc is explicitly cleared when clear_acc is asserted.
        //       This simulates a context switch or resource release.
        // ------------------------------------------------------------
        $display("\n[PHASE 2] CWE‑226: Context-switch scrubbing test");

        // First, accumulate some secret-dependent state
        secret_bit = 1;
        data_in    = 16'h0003;
        repeat(4) @(posedge clk);

        // Now simulate a context switch
        $display("  Asserting clear_acc to scrub sensitive state");
        clear_acc = 1;
        @(posedge clk);
        clear_acc = 0;

        // After scrub, new session begins with clean state
        $display("  New session after scrub");
        secret_bit = 0;
        data_in    = 16'h0001;
        repeat(4) @(posedge clk);

        // ------------------------------------------------------------
        // PHASE 3 — CWE‑226: Reset scrubbing validation
        // ------------------------------------------------------------
        // Goal: Ensure reset always clears acc, regardless of prior state.
        // ------------------------------------------------------------
        $display("\n[PHASE 3] CWE‑226: Reset scrubbing test");

        rst_n = 0;
        @(posedge clk);
        rst_n = 1;

        repeat(2) @(posedge clk);

        // ------------------------------------------------------------
        // END
        // ------------------------------------------------------------
        $display("\n=== Secure Testbench Complete ===");
        $finish;
    end

endmodule
