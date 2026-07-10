`include "fixed.v"

`timescale 1ns/1ps

module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg  [7:0]  secret_data;
    reg         privileged;
    reg         secure_mode;
    reg         lock_fuse;
    reg         glitch_detect;

    wire [7:0]  acc_internal;
    wire [7:0]  acc_public;
    wire        error;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .secret_bit(secret_bit),
        .secret_data(secret_data),
        .privileged(privileged),
        .secure_mode(secure_mode),
        .lock_fuse(lock_fuse),
        .glitch_detect(glitch_detect),
        .acc_internal(acc_internal),
        .acc_public(acc_public),
        .error(error)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        $display("=== Fixed CWE Security Validation Testbench Start ===");

        // Common init
        rst_n        = 0;
        secret_bit   = 0;
        secret_data  = 0;
        privileged   = 1;   // start as privileged
        secure_mode  = 0;
        lock_fuse    = 0;
        glitch_detect= 0;
        #12 rst_n    = 1;

        // -------------------------------
        // CWE-226: scrubbing on context change
        // -------------------------------
        $display("\n[CWE-226] Testing scrubbing on secure_mode exit...");
        secure_mode  = 1;
        secret_bit   = 1;
        secret_data  = 8'hA5;
        #10;
        $display("acc_internal during secure operation: %h", acc_internal);

        // Exit secure context -> should scrub
        secure_mode  = 0;
        #10;
        $display("acc_internal after secure_mode exit (should be 00): %h", acc_internal);

        // -------------------------------
        // CWE-1262 / CWE-1256: access control
        // -------------------------------
        $display("\n[CWE-1262 / CWE-1256] Testing masked public access...");
        // Re-enter secure mode, privileged
        secure_mode  = 1;
        secret_bit   = 1;
        secret_data  = 8'h3C;
        #10;
        $display("acc_internal (privileged, secure): %h", acc_internal);
        $display("acc_public   (privileged, secure): %h", acc_public);

        // Drop privilege -> public view must be masked
        privileged   = 0;
        #10;
        $display("acc_internal (unprivileged): %h", acc_internal);
        $display("acc_public   (unprivileged, should be 00): %h", acc_public);

        // -------------------------------
        // CWE-1234: reset should not override locked secrets
        // -------------------------------
        $display("\n[CWE-1234] Testing lock_fuse vs reset override...");
        privileged   = 1;
        secure_mode  = 1;
        lock_fuse    = 1;   // lock set: reset must not clear internal secret
        secret_bit   = 1;
        secret_data  = 8'hE1;
        #10;
        $display("acc_internal before reset (locked): %h", acc_internal);

        rst_n = 0; #10; rst_n = 1; #10;
        $display("acc_internal after reset (locked, should retain or be protected): %h", acc_internal);
        $display("acc_public   after reset (default-deny, should be 00 unless privileged+secure): %h", acc_public);

        // -------------------------------
        // CWE-1247: glitch detection forces safe state
        // -------------------------------
        $display("\n[CWE-1247] Testing glitch_detect safe state...");
        secure_mode   = 1;
        privileged    = 1;
        lock_fuse     = 0;
        glitch_detect = 0;
        secret_bit    = 1;
        secret_data   = 8'h0F;
        #10;
        $display("acc_internal before glitch: %h", acc_internal);

        glitch_detect = 1;  // fault injected
        #10;
        $display("error after glitch (should be 1): %b", error);
        $display("acc_internal after glitch (should be scrubbed): %h", acc_internal);
        $display("acc_public   after glitch (should be 00): %h", acc_public);

        $display("\n=== Fixed Testbench Complete ===");
        $finish;
    end

endmodule
