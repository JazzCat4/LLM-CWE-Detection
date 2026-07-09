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
        $display("=== Secure DUT Testbench (CWE-226 & CWE-1300) ===");

        // Init
        rst_n      = 0;
        secret_bit = 0;
        clear_acc  = 0;
        data_in    = 0;

        repeat(2) @(posedge clk);
        rst_n = 1;

        // --- CWE-1300: secret-dependent mux only, both branches active ---
        $display("\n--- CWE-1300: Secret-controlled mux test ---");
        data_in = 16'h00F0;

        secret_bit = 1;
        repeat(4) @(posedge clk);

        secret_bit = 0;
        repeat(4) @(posedge clk);

        // --- CWE-226: residual state scrub via clear_acc (context switch) ---
        $display("\n--- CWE-226: Context-switch scrubbing test ---");
        secret_bit = 1;
        data_in    = 16'h0003;
        repeat(4) @(posedge clk);

        // Context switch: assert clear_acc to scrub acc
        clear_acc = 1;
        @(posedge clk);
        clear_acc = 0;

        // New "user/session" after scrub
        secret_bit = 0;
        data_in    = 16'h0001;
        repeat(4) @(posedge clk);

        // --- CWE-226: reset scrubbing still works ---
        $display("\n--- CWE-226: Reset scrubbing test ---");
        rst_n = 0;
        @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        $display("\n=== Secure Testbench Complete ===");
        $finish;
    end

endmodule
