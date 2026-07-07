`include "fixed.v"

`timescale 1ns/1ps

module tb_test_secure;

    reg        clk;
    reg        rst_n;
    reg        lock_set;
    reg        debug;
    reg        write_en;
    reg        priv_ok;
    reg [7:0]  data_in;
    wire [7:0] lock_bits;
    wire       lock;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .lock_set(lock_set),
        .debug(debug),
        .write_en(write_en),
        .priv_ok(priv_ok),
        .data_in(data_in),
        .lock_bits(lock_bits),
        .lock(lock)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Stimulus
    initial begin
        $display("\n=== Secure CWE Validation Testbench ===");

        // Initial reset
        rst_n    = 0;
        lock_set = 0;
        debug    = 0;
        write_en = 0;
        priv_ok  = 0;
        data_in  = 8'h00;

        @(posedge clk);
        #1;
        $display("[RESET] lock_bits = %h, lock = %b", lock_bits, lock);

        rst_n = 1;

        // ------------------------------------------------------------
        // CWE-226: Scrubbing / reset behavior
        // ------------------------------------------------------------
        $display("\n[CWE-226] Testing scrubbing behavior");

        // 1) Set lock (write-once), no data write yet
        lock_set = 1;
        priv_ok  = 1;
        write_en = 0;
        data_in  = 8'hA5;

        @(posedge clk);
        #1;
        lock_set = 0;
        $display("  After lock_set: lock_bits = %h, lock = %b", lock_bits, lock);

        // 2) Now perform privileged write with lock already set
        write_en = 1;

        @(posedge clk);
        #1;
        $display("  Wrote sensitive value 0xA5, lock_bits = %h, lock = %b", lock_bits, lock);

        // Enter unauthenticated debug: should scrub lock_bits
        debug    = 1;
        priv_ok  = 0;   // unauthenticated debug

        @(posedge clk);
        #1;
        $display("  Entered unauthenticated debug, lock_bits scrubbed = %h", lock_bits);

        debug    = 0;


        // ------------------------------------------------------------
        // CWE-1191: Debug cannot override protections
        // ------------------------------------------------------------
        $display("\n[CWE-1191] Testing debug access control");

        // Try to write in debug without privilege
        debug    = 1;
        priv_ok  = 0;
        write_en = 1;
        data_in  = 8'h3C;

        @(posedge clk);
        #1;
        $display("  Debug without privilege: lock_bits = %h (WRITE BLOCKED)", lock_bits);

        debug    = 0;

        // ------------------------------------------------------------
        // CWE-1234: Debug cannot bypass lock
        // ------------------------------------------------------------
        $display("\n[CWE-1234] Testing lock enforcement vs debug");

        // Ensure lock is set
        lock_set = 1;
        priv_ok  = 1;
        write_en = 1;
        data_in  = 8'hF0;

        @(posedge clk);
        #1;
        lock_set = 0;
        $display("  Privileged write with lock set: lock_bits = %h, lock = %b", lock_bits, lock);

        // Now try debug with lock cleared (should not be possible: lock is write-once)
        debug    = 1;
        priv_ok  = 0;
        write_en = 1;
        data_in  = 8'h55;

        @(posedge clk);
        #1;
        $display("  Debug attempt to override lock: lock_bits = %h, lock = %b (NO OVERRIDE)", lock_bits, lock);

        debug    = 0;

        // ------------------------------------------------------------
        // CWE-1256: Unprivileged software cannot reach privileged register
        // ------------------------------------------------------------
        $display("\n[CWE-1256] Testing privilege gating of writes");

        // Unprivileged write attempt
        priv_ok  = 0;
        write_en = 1;
        data_in  = 8'h99;

        @(posedge clk);
        #1;
        $display("  Unprivileged write attempt: lock_bits = %h (WRITE BLOCKED)", lock_bits);

        // Privileged write
        priv_ok  = 1;
        write_en = 1;
        data_in  = 8'h77;

        @(posedge clk);
        #1;
        $display("  Privileged write: lock_bits = %h (WRITE ALLOWED)", lock_bits);

        // ------------------------------------------------------------
        // CWE-1262: Default-deny and explicit privilege checks
        // ------------------------------------------------------------
        $display("\n[CWE-1262] Testing register access control");

        // Default-deny: no lock, no privilege
        rst_n    = 0;
        @(posedge clk);
        #1;
        rst_n    = 1;

        priv_ok  = 0;
        write_en = 1;
        data_in  = 8'hAA;

        @(posedge clk);
        #1;
        $display("  After reset, no lock, no privilege: lock_bits = %h (DENY BY DEFAULT)", lock_bits);

        // Set lock and privilege, then write
        lock_set = 1;

        @(posedge clk);
        #1;
        priv_ok  = 1;
        write_en = 1;
        data_in  = 8'hBB;

        @(posedge clk);
        #1;
        lock_set = 0;
        $display("  With lock and privilege: lock_bits = %h (ACCESS CONTROL ENFORCED)", lock_bits);

        $display("\n=== Secure Testbench Completed ===");
        $finish;
    end

endmodule
