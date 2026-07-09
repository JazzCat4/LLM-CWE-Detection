`timescale 1ns/1ps

module tb_test;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg  [7:0]  secret_data;
    wire [7:0]  acc;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .secret_bit(secret_bit),
        .secret_data(secret_data),
        .acc(acc)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Test sequence
    initial begin
        $display("=== CWE Security Validation Testbench Start ===");

        // -------------------------------
        // CWE-226: Sensitive data persists across reuse
        // -------------------------------
        rst_n = 0; secret_bit = 0; secret_data = 0;
        #12 rst_n = 1;

        // Inject secret data
        secret_bit = 1;
        secret_data = 8'hA5;   // secret value
        #10;

        $display("[CWE-226] After secret injection, acc = %h", acc);

        // Disable secret mode (simulate context switch)
        secret_bit = 0;
        #20;

        $display("[CWE-226] After context switch (no scrub), acc still = %h", acc);

        // -------------------------------
        // CWE-226: Reset scrubbing validation
        // -------------------------------
        rst_n = 0; #10;
        $display("[CWE-226] After reset, acc = %h (should be 00)", acc);

        rst_n = 1; #10;

        // Reuse module without scrubbing
        secret_bit = 1;
        secret_data = 8'h3C;
        #10;

        $display("[CWE-226] After reuse, acc = %h (should not contain old secrets)", acc);

        // -------------------------------
        // CWE-1256: Unprivileged access to secret-processing controls
        // -------------------------------
        // Simulate unprivileged software toggling secret_bit
        secret_bit = 1;  // attacker enables secret processing
        secret_data = 8'hF0;
        #10;

        $display("[CWE-1256] Unprivileged toggle: acc = %h", acc);

        // -------------------------------
        // CWE-1262: Unprotected read of secret-derived register
        // -------------------------------
        $display("[CWE-1262] Read acc (secret-derived) = %h", acc);

        // Simulate attacker reading repeatedly
        #10 $display("[CWE-1262] Attacker read #2: acc = %h", acc);
        #10 $display("[CWE-1262] Attacker read #3: acc = %h", acc);

        // -------------------------------
        // CWE-1262: Write path not protected
        // -------------------------------
        // Attacker injects arbitrary secret_data
        secret_bit = 1;
        secret_data = 8'h99;
        #10;

        $display("[CWE-1262] Attacker write path: acc = %h", acc);

        $display("=== CWE Security Validation Testbench End ===");
        $finish;
    end

endmodule
