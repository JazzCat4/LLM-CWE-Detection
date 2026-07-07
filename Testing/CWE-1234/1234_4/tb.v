`include "1234_4.v"

`timescale 1ns/1ps

module tb_test;

    reg clk;
    reg lock;
    reg debug;
    reg write_en;
    reg [7:0] data_in;
    wire [7:0] lock_bits;

    // DUT
    test dut (
        .clk(clk),
        .lock(lock),
        .debug(debug),
        .write_en(write_en),
        .data_in(data_in),
        .lock_bits(lock_bits)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Test sequence
    initial begin
        $display("\n=== CWE Vulnerability Validation Testbench ===");

        // ------------------------------------------------------------
        // CWE-226: Sensitive register not cleared before reuse
        // ------------------------------------------------------------
        $display("\n[CWE-226] Testing lack of scrubbing / reset behavior");

        write_en = 1;
        lock     = 1;
        debug    = 0;
        data_in  = 8'hA5;   // sensitive value

        @(posedge clk);
        #1
        $display("  Wrote sensitive value 0xA5 into lock_bits = %h", lock_bits);

        // Now simulate context switch: disable lock, enable debug
        lock     = 0;
        debug    = 1;
        write_en = 0;

        @(posedge clk);
        #1
        $display("  After context switch, lock_bits still = %h (NO SCRUB!)", lock_bits);

        // ------------------------------------------------------------
        // CWE-1191: Debug interface overrides protections
        // ------------------------------------------------------------
        $display("\n[CWE-1191] Testing debug override of protected register");

        lock     = 0;       // lock disabled
        debug    = 1;       // debug enabled
        write_en = 1;
        data_in  = 8'h3C;

        @(posedge clk);
        #1
        $display("  Debug mode wrote 0x3C into lock_bits = %h (UNAUTHORIZED WRITE!)", lock_bits);

        // ------------------------------------------------------------
        // CWE-1234: Debug mode bypasses lock bit
        // ------------------------------------------------------------
        $display("\n[CWE-1234] Testing debug bypass of lock enforcement");

        lock     = 0;       // lock bit low
        debug    = 1;       // debug overrides lock
        write_en = 1;
        data_in  = 8'hF0;

        @(posedge clk);
        #1
        $display("  Debug bypassed lock and wrote 0xF0 into lock_bits = %h", lock_bits);

        // ------------------------------------------------------------
        // CWE-1256: Unprivileged software can modify privileged register
        // ------------------------------------------------------------
        $display("\n[CWE-1256] Testing unprivileged write to security register");

        // Simulate unprivileged software controlling write_en and data_in
        lock     = 0;
        debug    = 1;       // debug acts as unprivileged override
        write_en = 1;
        data_in  = 8'h55;

        @(posedge clk);
        #1
        $display("  Unprivileged write succeeded: lock_bits = %h", lock_bits);

        // ------------------------------------------------------------
        // CWE-1262: Improper access control for register interface
        // ------------------------------------------------------------
        $display("\n[CWE-1262] Testing missing privilege checks");

        lock     = 0;       // privileged path disabled
        debug    = 0;       // debug disabled
        write_en = 1;
        data_in  = 8'h99;

        @(posedge clk);
        #1
        $display("  Write_en=1 but lock/debug=0, write blocked (expected).");

        // Now assert debug to bypass privilege
        debug    = 1;
        @(posedge clk);
        #1
        $display("  Debug asserted: write now allowed, lock_bits = %h (PRIVILEGE BYPASS!)", lock_bits);

        $display("\n=== Testbench Completed ===");
        $finish;
    end

endmodule
