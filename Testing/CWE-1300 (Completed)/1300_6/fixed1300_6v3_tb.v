`timescale 1ns/1ps

module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg         clear_acc;
    reg  [15:0] data_in;
    wire [15:0] acc;

    reg [15:0] acc_add;
    reg [15:0] acc_sub;
    reg [15:0] acc_before_scrub;
    reg [15:0] acc_after_scrub;
    reg [15:0] acc_before_reset;
    reg [15:0] acc_after_reset;


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

    // PASS/FAIL helper
    task check;
    input [255:0] name;
    input [1:0] condition;
        if (condition)
            $display("  [PASS] %s", name);
        else
            $display("  [FAIL] %s", name);
    endtask

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
        // PHASE 1 — CWE‑1300: Constant‑Time Behavior Validation
        // ------------------------------------------------------------
        $display("\n[PHASE 1] CWE‑1300: Constant-time datapath test");
        $display("  Purpose: Ensure secret_bit only affects mux selection, not timing.");

        data_in = 16'h00F0;

        // Secret = 1 (ADD)
        secret_bit = 1;
        @(posedge clk);
        acc_add = acc;

        repeat(3) @(posedge clk);

        // Secret = 0 (SUB)
        secret_bit = 0;
        @(posedge clk);
        acc_sub = acc;

        repeat(3) @(posedge clk);

        // PASS/FAIL: Both branches must update acc every cycle
        check("acc updates under secret_bit=1", acc_add != 16'd0);
        check("acc updates under secret_bit=0", acc_sub != 16'd0);

        // ------------------------------------------------------------
        // PHASE 2 — CWE‑226: Context‑Switch Scrubbing
        // ------------------------------------------------------------
        $display("\n[PHASE 2] CWE‑226: Context-switch scrubbing test");
        $display("  Purpose: Ensure acc is cleared when clear_acc is asserted.");

        // Accumulate secret-dependent state
        secret_bit = 1;
        data_in    = 16'h0003;
        repeat(4) @(posedge clk);

        acc_before_scrub = acc;

        // Scrub
        clear_acc = 1;
        @(posedge clk);
        clear_acc = 0;

        acc_after_scrub = acc;
        // PASS/FAIL: acc must be zero after scrub
        check("acc contains secret-derived value before scrub", acc_before_scrub != 16'd0);
        check("acc is zero after clear_acc scrub", acc_after_scrub == 16'd0);

        // ------------------------------------------------------------
        // PHASE 3 — CWE‑226: Reset Scrubbing
        // ------------------------------------------------------------
        $display("\n[PHASE 3] CWE‑226: Reset scrubbing test");
        $display("  Purpose: Ensure acc is cleared on reset regardless of prior state.");

        // Create non-zero state
        secret_bit = 1;
        data_in    = 16'h0005;
        repeat(3) @(posedge clk);

        acc_before_reset = acc;

        // Apply reset
        rst_n = 0;
        @(posedge clk);
        rst_n = 1;

        repeat(1) @(posedge clk);
        acc_after_reset = acc;

        // PASS/FAIL: acc must be zero after reset
        check("acc contains non-zero value before reset", acc_before_reset != 16'd0);
        check("acc is zero after reset", acc_after_reset == 16'd0);

        // ------------------------------------------------------------
        // END
        // ------------------------------------------------------------
        $display("\n=== Secure Testbench Complete ===");
        $finish;
    end

endmodule
