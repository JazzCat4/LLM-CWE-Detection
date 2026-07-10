`include "1300_5.v"

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

    // Clock generation (allows glitch injection)
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Main stimulus
    initial begin
        $display("=== CWE Security Validation Testbench Start ===");

        // -------------------------------
        // CWE-226: Sensitive data not scrubbed
        // -------------------------------
        $display("\n[CWE-226] Testing lack of scrubbing...");
        rst_n = 0; secret_bit = 0; secret_data = 0;
        #12 rst_n = 1;

        // Inject secret
        secret_bit = 1;
        secret_data = 8'hA5;
        #10;

        // Stop secret operation but DO NOT reset
        secret_bit = 0;
        #10;

        // Check if secret-derived value still present
        $display("acc after secret operation (should be scrubbed): %h", acc);

        // -------------------------------
        // CWE-1262 / CWE-1256: No access control
        // -------------------------------
        $display("\n[CWE-1262 / CWE-1256] Testing unrestricted read access...");
        $display("Reading acc directly (should be protected): %h", acc);

        // -------------------------------
        // CWE-1234: Reset overrides security state
        // -------------------------------
        $display("\n[CWE-1234] Testing reset override of secret state...");
        secret_bit = 1;
        secret_data = 8'h3C;
        #10;

        $display("acc before forced reset: %h", acc);
        rst_n = 0;  // attacker toggles reset
        #5;
        $display("acc after forced reset (should not be externally clearable): %h", acc);
        rst_n = 1;

        // -------------------------------
        // CWE-1247: Clock glitch vulnerability
        // -------------------------------
        $display("\n[CWE-1247] Injecting clock glitch...");
        secret_bit = 1;
        secret_data = 8'h0F;
        #7;

        // Inject glitch: very short pulse
        clk = 1; #1; clk = 0; #1; clk = 1;

        #10;
        $display("acc after glitch (should be glitch-resistant): %h", acc);

        $display("\n=== Testbench Complete ===");
        $finish;
    end

endmodule
