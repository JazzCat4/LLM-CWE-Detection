`include "Example1.v"

`timescale 1ns/1ps

module Ex1_tb;

    // DUT inputs
    reg         clk;
    reg         reset;
    reg         sys_we;
    reg  [7:0]  sys_wdata;
    reg         dbg_mode;
    reg  [7:0]  dbg_cmd;
    reg  [7:0]  dbg_wdata;

    // DUT outputs
    wire [7:0]  secure_reg;
    wire        lock;

    // Instantiate DUT
    Ex1 dut (
        .clk        (clk),
        .reset      (reset),
        .sys_we     (sys_we),
        .sys_wdata  (sys_wdata),
        .dbg_mode   (dbg_mode),
        .dbg_cmd    (dbg_cmd),
        .dbg_wdata  (dbg_wdata),
        .secure_reg (secure_reg),
        .lock       (lock)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk; // 100 MHz
    end

    // Common tasks
    task apply_reset;
    begin
        reset = 1;
        sys_we = 0;
        sys_wdata = 8'h00;
        dbg_mode = 0;
        dbg_cmd  = 8'h00;
        dbg_wdata = 8'h00;
        #20;
        reset = 0;
        #20;
    end
    endtask

    task dbg_unlock;
    begin
        dbg_mode = 1;
        dbg_cmd  = 8'hAA; // unlock command
        #10;
        dbg_mode = 0;
        dbg_cmd  = 8'h00;
        #10;
    end
    endtask

    task dbg_write(input [7:0] val);
    begin
        dbg_mode  = 1;
        dbg_cmd   = 8'hBB; // debug write command
        dbg_wdata = val;
        #10;
        dbg_mode  = 0;
        dbg_cmd   = 8'h00;
        dbg_wdata = 8'h00;
        #10;
    end
    endtask

    task sys_write(input [7:0] val);
    begin
        sys_we    = 1;
        sys_wdata = val;
        #10;
        sys_we    = 0;
        sys_wdata = 8'h00;
        #10;
    end
    endtask

    // Test sequences
    initial begin
        $display("=== Ex1 Vulnerability Testbench ===");

        // Initialize
        reset    = 0;
        sys_we   = 0;
        sys_wdata= 8'h00;
        dbg_mode = 0;
        dbg_cmd  = 8'h00;
        dbg_wdata= 8'h00;

        // ------------------------------------------------------------
        // 1) CWE-1191: Debug interface with improper access control
        //    - Show that debug alone (dbg_mode/dbg_cmd) can write sensitive register
        // ------------------------------------------------------------
        $display("\n[TEST 1] CWE-1191: Unauthenticated debug write to secure_reg");
        apply_reset;
        $display("  After reset: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Attempt debug write while locked
        dbg_write(8'hA5);
        $display("  After dbg_write(0xA5): lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // ------------------------------------------------------------
        // 2) CWE-1234: Debug overrides lock bit and bypasses lock enforcement
        // ------------------------------------------------------------
        $display("\n[TEST 2] CWE-1234: Debug unlock and lock bypass");
        apply_reset;
        $display("  After reset: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Unlock via debug
        dbg_unlock;
        $display("  After dbg_unlock: lock=%0b (expected 0 if vulnerable)", lock);

        // System write now succeeds because lock cleared
        sys_write(8'h3C);
        $display("  After sys_write(0x3C): lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Debug write ignoring lock
        dbg_write(8'h5A);
        $display("  After dbg_write(0x5A): lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // ------------------------------------------------------------
        // 3) CWE-1256: Software-accessible interfaces to hardware features
        //    - Show that any entity driving dbg_* or sys_* can change sensitive state
        // ------------------------------------------------------------
        $display("\n[TEST 3] CWE-1256: Unprivileged-like access to sensitive features");
        apply_reset;
        $display("  After reset: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Treat dbg_* as unprivileged software interface
        dbg_write(8'hF0);
        $display("  Unprivileged dbg_write(0xF0): lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        dbg_unlock;
        sys_write(8'h0F);
        $display("  Unprivileged sys_write(0x0F) after dbg_unlock: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // ------------------------------------------------------------
        // 4) CWE-226: Sensitive information not removed before reuse
        //    - Show that secure_reg retains old sensitive value until overwritten/reset
        // ------------------------------------------------------------
        $display("\n[TEST 4] CWE-226: Residual data in secure_reg");
        apply_reset;
        dbg_write(8'hDE); // write sensitive value
        $display("  After dbg_write(0xDE): secure_reg=0x%0h", secure_reg);

        // Reuse secure_reg via system write without explicit clear
        dbg_unlock;
        sys_write(8'hAD);
        $display("  After sys_write(0xAD): secure_reg=0x%0h (previous 0xDE overwritten, no scrub)", secure_reg);

        // ------------------------------------------------------------
        // 5) CWE-1262: Improper access control for register interface
        //    - Show lock can be cleared after being set and not enforced on all paths
        // ------------------------------------------------------------
        $display("\n[TEST 5] CWE-1262: Lock bit is not one-way and not universally enforced");
        apply_reset;
        $display("  After reset: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Clear lock via debug
        dbg_unlock;
        $display("  After dbg_unlock: lock=%0b (should remain 1 in secure design)", lock);

        // Debug write ignoring lock
        dbg_write(8'h99);
        $display("  Debug write to secure_reg ignoring lock: secure_reg=0x%0h", secure_reg);

        // ------------------------------------------------------------
        // 6) CWE-1247: No protection against clock glitches
        //    - We can't inject real glitches here, but we can show single-cycle decisions
        // ------------------------------------------------------------
        $display("\n[TEST 6] CWE-1247: Single-cycle security decisions (no glitch hardening)");
        apply_reset;
        $display("  After reset: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        // Single-cycle unlock and write
        dbg_mode  = 1;
        dbg_cmd   = 8'hAA; // unlock
        #10;               // one cycle
        dbg_cmd   = 8'hBB; // write
        dbg_wdata = 8'hCC;
        #10;
        dbg_mode  = 0;
        dbg_cmd   = 8'h00;
        dbg_wdata = 8'h00;
        #10;
        $display("  After single-cycle unlock+write sequence: lock=%0b, secure_reg=0x%0h", lock, secure_reg);

        $display("\n=== Tests complete ===");
        #50;
        $finish;
    end

endmodule
