`include "cwe1262_buggy.v"
`timescale 1ns/1ps
// 6/24/26
module periph_regs_buggy_cwe_tb;

    reg         clk;
    reg         rst_n;
    reg         reg_wen;
    reg         reg_ren;
    reg  [2:0]  reg_addr;
    reg  [31:0] reg_wdata;
    wire [31:0] reg_rdata;

    reg  [1:0]  cpu_privilege_level;
    reg         user_mode;

    wire [31:0] crypto_key;
    wire [31:0] security_config;

    // DUT
    periph_regs_buggy dut (
        .clk(clk),
        .rst_n(rst_n),
        .reg_wen(reg_wen),
        .reg_ren(reg_ren),
        .reg_addr(reg_addr),
        .reg_wdata(reg_wdata),
        .reg_rdata(reg_rdata),
        .cpu_privilege_level(cpu_privilege_level),
        .user_mode(user_mode),
        .crypto_key(crypto_key),
        .security_config(security_config)
    );

    // Clock
    always #5 clk = ~clk;

    // Simple write task
    task write_reg(input [2:0] addr, input [31:0] data);
    begin
        reg_addr = addr;
        reg_wdata = data;
        reg_wen = 1;
        @(posedge clk);
        reg_wen = 0;
    end
    endtask

    // Simple read task
    task read_reg(input [2:0] addr);
    begin
        reg_addr = addr;
        reg_ren = 1;
        @(posedge clk);
        reg_ren = 0;
    end
    endtask

    initial begin
        $display("\n=== Starting CWE Testbench ===");

        clk = 0;
        rst_n = 0;
        reg_wen = 0;
        reg_ren = 0;
        cpu_privilege_level = 2'b00; // unprivileged
        user_mode = 1'b1;

        repeat(2) @(posedge clk);
        rst_n = 1;

        // ------------------------------------------------------------
        //  CWE‑226: Sensitive information not removed before reuse
        // ------------------------------------------------------------
        $display("\n[CWE‑226] Testing for leftover sensitive data...");

        // Step 1: Write a known pattern to crypto_key_reg
        write_reg(3'h1, 32'hFACE_CAFE);

        // Step 2: Overwrite with new data WITHOUT zeroization
        write_reg(3'h1, 32'h1111_2222);

        // Step 3: Read back to see if old data leaked
        read_reg(3'h1);
        @(posedge clk);
        $display("[CWE‑226] crypto_key readback = %h", reg_rdata);

        // ------------------------------------------------------------
        //  CWE‑1262: Improper access control for register interface
        // ------------------------------------------------------------
        $display("\n[CWE‑1262] Testing unprivileged access to sensitive registers...");

        cpu_privilege_level = 2'b00; // force unprivileged
        user_mode = 1'b1;

        // Attempt to write secret registers
        write_reg(3'h0, 32'hBAD0_BAD0); // security_config_reg
        write_reg(3'h1, 32'hBAD1_BAD1); // crypto_key_reg

        // Attempt to read secret registers
        read_reg(3'h0);
        @(posedge clk);
        $display("[CWE‑1262] security_config readback = %h", reg_rdata);

        read_reg(3'h1);
        @(posedge clk);
        $display("[CWE‑1262] crypto_key readback = %h", reg_rdata);

        // ------------------------------------------------------------
        //  CWE‑1256: Improper restriction of software interfaces
        // ------------------------------------------------------------
        $display("\n[CWE‑1256] Testing unprivileged manipulation of hardware-only features...");

        // Unprivileged software attempts to reprogram hardware security config
        write_reg(3'h0, 32'h1234_5678);

        // Read back to confirm write succeeded (it should NOT in a secure design)
        read_reg(3'h0);
        @(posedge clk);
        $display("[CWE‑1256] security_config after unpriv write = %h", reg_rdata);

        // Unprivileged software attempts to inject a new crypto key
        write_reg(3'h1, 32'hABCD_EF01);

        read_reg(3'h1);
        @(posedge clk);
        $display("[CWE‑1256] crypto_key after unpriv write = %h", reg_rdata);

        $display("\n=== CWE Testbench Complete ===\n");
        $finish;
    end

endmodule
