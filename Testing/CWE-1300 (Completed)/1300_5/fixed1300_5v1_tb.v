`timescale 1ns/1ps

module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         priv_secure;
    reg         secret_bit;
    reg  [7:0]  secret_data;
    reg         clear_acc;
    wire [7:0]  acc;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .priv_secure(priv_secure),
        .secret_bit(secret_bit),
        .secret_data(secret_data),
        .clear_acc(clear_acc),
        .acc(acc)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        $display("=== Hardened CWE Security Validation Testbench Start ===");

        // Initial reset
        rst_n = 0; priv_secure = 0; secret_bit = 0; secret_data = 0; clear_acc = 0;
        #12 rst_n = 1;

        // -------------------------------
        // CWE-226: secret injection and scrub on context switch
        // -------------------------------
        priv_secure = 1;
        secret_bit  = 1;
        secret_data = 8'hA5;
        #10;
        $display("[CWE-226] After secret injection, acc (priv) = %h", acc);

        // Context switch: clear_acc asserted
        clear_acc = 1; #10;
        clear_acc = 0; #10;
        $display("[CWE-226] After context switch scrub, acc = %h (should be 00)", acc);

        // -------------------------------
        // CWE-226: reset scrubbing
        // -------------------------------
        secret_bit  = 1;
        secret_data = 8'h3C;
        #10;
        $display("[CWE-226] Before reset, acc = %h", acc);

        rst_n = 0; #10;
        rst_n = 1; #10;
        $display("[CWE-226] After reset, acc = %h (should be 00)", acc);

        // -------------------------------
        // CWE-1256: unprivileged toggle should NOT enable secret processing
        // -------------------------------
        priv_secure = 0; // unprivileged
        secret_bit  = 1;
        secret_data = 8'hF0;
        #20;
        $display("[CWE-1256] Unprivileged toggle: acc = %h (should remain 00)", acc);

        // -------------------------------
        // CWE-1262: read path default-deny when unprivileged
        // -------------------------------
        priv_secure = 1;
        secret_bit  = 1;
        secret_data = 8'h10;
        #10;
        $display("[CWE-1262] Privileged read: acc = %h", acc);

        priv_secure = 0; #10;
        $display("[CWE-1262] Unprivileged read: acc = %h (should be 00)", acc);

        // Explicit scrub before reuse
        priv_secure = 1; clear_acc = 1; #10;
        clear_acc = 0; #10;
        $display("[CWE-226/CWE-1262] After scrub + privileged, acc = %h (should be 00)", acc);

        $display("=== Hardened CWE Security Validation Testbench End ===");
        $finish;
    end

endmodule
