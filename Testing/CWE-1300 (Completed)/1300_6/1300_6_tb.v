`timescale 1ns/1ps

module tb_test;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg  [15:0] data_in;
    wire [15:0] acc;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .secret_bit(secret_bit),
        .data_in(data_in),
        .acc(acc)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz clock
    end

    // Stimulus
    initial begin
        $display("=== CWE-226 & CWE-1300 Vulnerability Testbench ===");

        // 1. Global reset
        rst_n = 0;
        secret_bit = 0;
        data_in = 0;
        repeat(2) @(posedge clk);
        rst_n = 1;

        // ---------------------------------------------------------
        // CWE-1300 TEST: Secret-dependent switching activity
        // ---------------------------------------------------------
        // Apply identical data_in but toggle secret_bit
        // Expect: acc evolution differs → power/timing leakage
        $display("\n--- CWE-1300: Secret-dependent behavior test ---");

        data_in = 16'h00F0;

        secret_bit = 1;  // ADD path
        repeat(4) @(posedge clk);

        secret_bit = 0;  // SUB path
        repeat(4) @(posedge clk);

        // ---------------------------------------------------------
        // CWE-226 TEST: Residual sensitive state not scrubbed
        // ---------------------------------------------------------
        // Simulate "context switch" without asserting rst_n
        // Expect: acc retains secret-derived values
        $display("\n--- CWE-226: Residual state test (no scrub) ---");

        secret_bit = 1;
        data_in = 16'h0003;
        repeat(4) @(posedge clk);

        // Context switch: new user/session
        // No reset → acc still contains secret-derived state
        secret_bit = 0;
        data_in = 16'h0001;
        repeat(4) @(posedge clk);

        // ---------------------------------------------------------
        // CWE-226 TEST: Reset scrubbing validation
        // ---------------------------------------------------------
        $display("\n--- CWE-226: Reset scrubbing test ---");

        rst_n = 0;   // Should scrub acc
        @(posedge clk);
        rst_n = 1;

        // Check if acc is zero after reset
        repeat(2) @(posedge clk);

        // ---------------------------------------------------------
        // CWE-1300 TEST: Differential power/timing analysis stimulus
        // ---------------------------------------------------------
        $display("\n--- CWE-1300: DPA stimulus ---");

        // Repeated toggling of secret_bit with controlled data_in
        // Used for offline power/timing correlation analysis
        data_in = 16'h00FF;

        repeat(8) begin
            secret_bit = 1;
            @(posedge clk);
            secret_bit = 0;
            @(posedge clk);
        end

        $display("\n=== Testbench Complete ===");
        $finish;
    end

endmodule

