`timescale 1ns/1ps
`include "fixed1.v"

module Ex1_secure_tb;

    // DUT inputs
    reg         clk;
    reg         reset;
    reg         sys_we;
    reg  [7:0]  sys_wdata;
    reg         sys_priv;

    reg         dbg_mode_req;
    reg         dbg_auth_ok;
    reg         dbg_lifecycle_dev;
    reg  [7:0]  dbg_cmd;
    reg  [7:0]  dbg_wdata;

    reg         glitch_detected;

    // DUT outputs
    wire [7:0]  secure_reg;
    wire        lock;

    // Instantiate DUT
    Ex1_secure dut (
        .clk(clk),
        .reset(reset),
        .sys_we(sys_we),
        .sys_wdata(sys_wdata),
        .sys_priv(sys_priv),
        .dbg_mode_req(dbg_mode_req),
        .dbg_auth_ok(dbg_auth_ok),
        .dbg_lifecycle_dev(dbg_lifecycle_dev),
        .dbg_cmd(dbg_cmd),
        .dbg_wdata(dbg_wdata),
        .glitch_detected(glitch_detected),
        .secure_reg(secure_reg),
        .lock(lock)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Common tasks
    task apply_reset;
    begin
        reset = 1;
        sys_we = 0;
        sys_wdata = 8'h00;
        sys_priv = 0;

        dbg_mode_req = 0;
        dbg_auth_ok = 0;
        dbg_lifecycle_dev = 0;
        dbg_cmd = 8'h00;
        dbg_wdata = 8'h00;

        glitch_detected = 0;

        #20;
        reset = 0;
        #20;
    end
    endtask

    task dbg_try_write(input [7:0] val);
    begin
        dbg_mode_req = 1;
        dbg_auth_ok = 1;
        dbg_lifecycle_dev = 1;
        dbg_cmd = 8'hBB;
        dbg_wdata = val;
        #10;

        dbg_mode_req = 0;
        dbg_auth_ok = 0;
        dbg_lifecycle_dev = 0;
        dbg_cmd = 8'h00;
        dbg_wdata = 8'h00;
        #10;
    end
    endtask

    task dbg_try_unlock;
    begin
        dbg_mode_req = 1;
        dbg_auth_ok = 1;
        dbg_lifecycle_dev = 1;
        dbg_cmd = 8'hAA;
        #10;

        dbg_mode_req = 0;
        dbg_auth_ok = 0;
        dbg_lifecycle_dev = 0;
        dbg_cmd = 8'h00;
        #10;
    end
    endtask

    task sys_write_priv(input [7:0] val);
    begin
        sys_priv = 1;
        sys_we = 1;
        sys_wdata = val;
        #10;

        sys_we = 0;
        sys_wdata = 8'h00;
        sys_priv = 0;
        #10;
    end
    endtask

    initial begin
        $display("=== Ex1_secure Hardened Module Testbench ===");

        // ------------------------------------------------------------
        // TEST 1 — CWE‑1191: Debug cannot write sensitive register
        // ------------------------------------------------------------
        $display("\n[TEST 1] Debug write must NOT modify secure_reg");
        apply_reset;
        dbg_try_write(8'hA5);
        $display("  secure_reg = 0x%0h (expected 00)", secure_reg);

        // ------------------------------------------------------------
        // TEST 2 — CWE‑1234: Debug cannot override lock bit
        // ------------------------------------------------------------
        $display("\n[TEST 2] Debug cannot unlock or modify lock");
        apply_reset;
        dbg_try_unlock;
        $display("  lock = %0b (expected 1)", lock);

        // ------------------------------------------------------------
        // TEST 3 — CWE‑1256: Unprivileged cannot modify sensitive features
        // ------------------------------------------------------------
        $display("\n[TEST 3] Unprivileged writes must NOT modify secure_reg");
        apply_reset;
        sys_we = 1;
        sys_wdata = 8'hF0;
        #10;
        sys_we = 0;
        $display("  secure_reg = 0x%0h (expected 00)", secure_reg);

        // ------------------------------------------------------------
        // TEST 4 — CWE‑226: Sensitive data cleared before reuse
        // ------------------------------------------------------------
        $display("\n[TEST 4] Sensitive data cleared on reset");
        apply_reset;
        sys_write_priv(8'hDE); // privileged write allowed only when lock=0
        $display("  secure_reg after privileged write attempt = 0x%0h (expected 00)", secure_reg);

        // Now unlock via privileged write (write 0xFF)
        sys_write_priv(8'hFF);
        sys_write_priv(8'hAD);
        $display("  secure_reg after privileged write with lock cleared = 0x%0h", secure_reg);

        apply_reset;
        $display("  secure_reg after reset = 0x%0h (expected 00)", secure_reg);

        // ------------------------------------------------------------
        // TEST 5 — CWE‑1262: Lock bit must be one-way and enforced
        // ------------------------------------------------------------
        $display("\n[TEST 5] Lock bit cannot be cleared except by privileged system logic");
        apply_reset;
        dbg_try_unlock;
        $display("  lock = %0b (expected 1)", lock);

        // ------------------------------------------------------------
        // TEST 6 — CWE‑1247: Glitch detection forces safe state
        // ------------------------------------------------------------
        $display("\n[TEST 6] Glitch detection forces secure state");
        apply_reset;

        // Unlock via privileged write
        sys_write_priv(8'hFF); // re-lock
        sys_write_priv(8'h00); // attempt unlock (should NOT unlock)
        $display("  lock before glitch = %0b (expected 1)", lock);

        glitch_detected = 1;
        #10;
        glitch_detected = 0;

        $display("  secure_reg after glitch = 0x%0h (expected 00)", secure_reg);
        $display("  lock after glitch = %0b (expected 1)", lock);

        $display("\n=== Hardened module tests complete ===");
        #50;
        $finish;
    end

endmodule
