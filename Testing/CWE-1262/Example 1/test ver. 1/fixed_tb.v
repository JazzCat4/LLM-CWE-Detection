`include "fixed.v"
`timescale 1ns/1ps

module fixed_tb;

    reg         clk;
    reg         rst_n;
    reg         reg_wen;
    reg         reg_ren;
    reg  [2:0]  reg_addr;
    reg  [31:0] reg_wdata;
    wire [31:0] reg_rdata;

    reg  [1:0]  cpu_privilege_level;
    reg         user_mode;
    reg         env_ok;

    wire [31:0] crypto_key;
    wire [31:0] security_config;

    // DUT
    periph_regs_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .reg_wen(reg_wen),
        .reg_ren(reg_ren),
        .reg_addr(reg_addr),
        .reg_wdata(reg_wdata),
        .reg_rdata(reg_rdata),
        .cpu_privilege_level(cpu_privilege_level),
        .user_mode(user_mode),
        .env_ok(env_ok),
        .crypto_key(crypto_key),
        .security_config(security_config)
    );

    // Clock
    always #5 clk = ~clk;

    // Tasks
    task write_reg(input [2:0] addr, input [31:0] data);
    begin
        reg_addr  = addr;
        reg_wdata = data;
        reg_wen   = 1;
        @(posedge clk);
        reg_wen   = 0;
    end
    endtask

    task read_reg(input [2:0] addr);
    begin
        reg_addr = addr;
        reg_ren  = 1;
        @(posedge clk);
        reg_ren  = 0;
    end
    endtask

    initial begin
        $dumpfile("fixed_tb.vcd");
        $dumpvars(0, fixed_tb);

        $display("\n=== Starting CWE Testbench for periph_regs_secure ===");

        clk = 0;
        rst_n = 0;
        reg_wen = 0;
        reg_ren = 0;
        reg_addr = 0;
        reg_wdata = 0;

        // Start in unprivileged, bad environment
        cpu_privilege_level = 2'b00;
        user_mode           = 1'b1;
        env_ok              = 1'b0;

        // Reset
        repeat(2) @(posedge clk);
        rst_n = 1;
        @(posedge clk);

        // ------------------------------------------------------------
        // CWE‑226: Sensitive information not removed before reuse
        // What to test:
        //  - Write known pattern to key
        //  - Lock/scrub
        //  - Verify no prior contents visible / key zeroed
        // ------------------------------------------------------------
        $display("\n[CWE‑226] Testing scrubbing on lock and reset...");

        // Move to privileged, good environment
        cpu_privilege_level = 2'b11;
        user_mode           = 1'b0;
        env_ok              = 1'b1;

        // Write known pattern to crypto_key_reg
        write_reg(3'h1, 32'hFACE_CAFE);
        @(posedge clk);
        $display("[CWE‑226] crypto_key (internal) after write = %h", crypto_key);

        // Set lock bit (addr 3, bit 0) → should scrub key
        write_reg(3'h3, 32'h0000_0001);
        @(posedge clk);
        $display("[CWE‑226] crypto_key (internal) after lock = %h", crypto_key);

        // Assert reset → key must be zero
        rst_n = 0;
        @(posedge clk);
        rst_n = 1;
        @(posedge clk);
        $display("[CWE‑226] crypto_key (internal) after reset = %h", crypto_key);

        // ------------------------------------------------------------
        // CWE‑1262: Improper access control for register interface
        // What to test:
        //  - From unprivileged mode, attempt read/write to every register
        //  - Confirm privileged registers not writable/readable
        // ------------------------------------------------------------
        $display("\n[CWE‑1262] Testing unprivileged access to sensitive CSRs...");

        // Unprivileged, user mode, env_ok = 1
        cpu_privilege_level = 2'b00;
        user_mode           = 1'b1;
        env_ok              = 1'b1;

        // Attempt to write security_config_reg (addr 0)
        write_reg(3'h0, 32'hBAD0_BAD0);
        @(posedge clk);
        // Try to read it back
        read_reg(3'h0);
        @(posedge clk);
        $display("[CWE‑1262] security_config read (unpriv) = %h", reg_rdata);

        // Attempt to write crypto_key_reg (addr 1)
        write_reg(3'h1, 32'hBAD1_BAD1);
        @(posedge clk);
        // Try to read it back (should always be 0)
        read_reg(3'h1);
        @(posedge clk);
        $display("[CWE‑1262] crypto_key read (unpriv, masked) = %h", reg_rdata);

        // Attempt to set lock bit (addr 3)
        write_reg(3'h3, 32'h0000_0001);
        @(posedge clk);
        // Privileged read of lock state via internal signal
        cpu_privilege_level = 2'b11;
        user_mode           = 1'b0;
        env_ok              = 1'b1;
        @(posedge clk);
        $display("[CWE‑1262] crypto_key (internal) after unpriv lock attempt = %h", crypto_key);
        // security_config should still be default (0) if lock didn't set

        // ------------------------------------------------------------
        // CWE‑1256: Improper restriction of SW interfaces to HW features
        // What to test:
        //  - Verify SW-accessible interfaces cannot directly manipulate
        //    hardware-only features from unprivileged mode
        // ------------------------------------------------------------
        $display("\n[CWE‑1256] Testing that hardware-only features are privilege-gated...");

        // Unprivileged again
        cpu_privilege_level = 2'b00;
        user_mode           = 1'b1;
        env_ok              = 1'b1;

        // Try to program security_config_reg (hardware control) from unprivileged SW
        write_reg(3'h0, 32'h1234_5678);
        @(posedge clk);

        // Privileged read to check whether unprivileged write had any effect
        cpu_privilege_level = 2'b11;
        user_mode           = 1'b0;
        env_ok              = 1'b1;
        read_reg(3'h0);
        @(posedge clk);
        $display("[CWE‑1256] security_config after unpriv write attempt = %h", reg_rdata);

        // Try to program crypto_key_reg from unprivileged SW
        cpu_privilege_level = 2'b00;
        user_mode           = 1'b1;
        env_ok              = 1'b1;
        write_reg(3'h1, 32'hABCD_EF01);
        @(posedge clk);

        // Privileged check of internal key
        cpu_privilege_level = 2'b11;
        user_mode           = 1'b0;
        env_ok              = 1'b1;
        @(posedge clk);
        $display("[CWE‑1256] crypto_key (internal) after unpriv write attempt = %h", crypto_key);

        $display("\n=== CWE Testbench for periph_regs_secure Complete ===\n");
        $finish;
    end

endmodule
