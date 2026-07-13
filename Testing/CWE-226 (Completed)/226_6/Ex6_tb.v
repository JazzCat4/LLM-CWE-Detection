`timescale 1ns/1ps

// Testbench for original insecure secret_fifo
// Exercises CWE-226, CWE-1234, CWE-1247, CWE-1256, CWE-1262, CWE-1300
module tb_secret_fifo_security;

    reg         clk, rst;
    reg         push, pop;
    reg [63:0]  key_in;
    wire [63:0] key_out;
    wire        empty, full;

    // DUT: original module
    secret_fifo dut (
        .clk    (clk),
        .rst    (rst),
        .push   (push),
        .pop    (pop),
        .key_in (key_in),
        .key_out(key_out),
        .empty  (empty),
        .full   (full)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk; // 100 MHz nominal
    end

    // Simple clock glitch (CWE-1247)
    task clock_glitch;
        begin
            // Inject extra edges out of phase
            #1 clk = ~clk;
            #1 clk = ~clk;
        end
    endtask

    // Helper tasks
    task push_key(input [63:0] val);
        begin
            key_in = val;
            push   = 1; #10 push = 0;
        end
    endtask

    task pop_key;
        begin
            pop = 1; #10 pop = 0;
        end
    endtask

    initial begin
        $display("=== SECURITY TESTBENCH FOR secret_fifo START ===");
        rst = 1; push = 0; pop = 0; key_in = 64'h0;
        #20 rst = 0;

        // ------------------------------------------------------------
        // CWE-226: Sensitive Information Not Removed Before Reuse
        // 1) Zero-fill on reset
        // 2) Overwrite keys after use
        // 3) Validate scrubbing before reuse
        // ------------------------------------------------------------
        $display("\n[CWE-226] Zeroization and scrubbing checks");

        // Write secret, pop once
        push_key(64'hDEADBEEF_F00DBAAD);
        pop_key();
        $display("First pop (secret) key_out = %h", key_out);

        // Pop again: if slot was scrubbed, should be 0; otherwise stale data
        pop_key();
        $display("Second pop (should be 0 if scrubbed) key_out = %h", key_out);

        // Reset should scrub all storage
        push_key(64'h1111222233334444);
        push_key(64'h5555666677778888);
        rst = 1; #10 rst = 0;

        pop_key();
        $display("Pop after reset (should be 0 if zero-filled) key_out = %h", key_out);

        // Reuse: write new key after reset, ensure no old data leaks
        push_key(64'h0000000000000001);
        pop_key();
        $display("Pop after reuse (should be new key only) key_out = %h", key_out);

        // ------------------------------------------------------------
        // CWE-1234: Debug/Internal Modes Override Locks
        // This module has NO lock bits, NO debug signals → structural failure.
        // Testbench simply demonstrates unrestricted access.
        // ------------------------------------------------------------
        $display("\n[CWE-1234] Lock/Debug override checks (structural)");

        $display("No lock bit or debug_mode signals exist in secret_fifo.");
        $display("Any push/pop is allowed; no way to set or enforce a lock.");

        push_key(64'hAAAAAAAAAAAAAAAA);
        pop_key();
        $display("Unrestricted access key_out = %h (should require lock/priv)", key_out);

        // ------------------------------------------------------------
        // CWE-1247: Voltage/Clock Glitch Protection
        // Inject clock glitches and observe that design has no error/safe state.
        // ------------------------------------------------------------
        $display("\n[CWE-1247] Clock glitch behavior");

        rst = 1; #10 rst = 0;
        push_key(64'h123456789ABCDEF0);

        $display("Injecting clock glitch...");
        clock_glitch();
        #10;

        // After glitch, try normal operations
        push_key(64'h0F0F0F0F0F0F0F0F);
        pop_key();
        $display("After glitch, key_out = %h (no glitch detection / safe state)", key_out);

        // ------------------------------------------------------------
        // CWE-1256 / CWE-1262: Software Interface & Access Control
        // There is no privilege level, no access control → default-open.
        // ------------------------------------------------------------
        $display("\n[CWE-1256/CWE-1262] Privilege and access control checks");

        // Treat this as "unprivileged" context: still can push/pop freely
        push_key(64'hCAFEBABECAFEBABE);
        pop_key();
        $display("Unprivileged-like access key_out = %h (should be fault/denied)", key_out);

        // No way to mark registers as privileged-only; all accesses succeed.

        // ------------------------------------------------------------
        // CWE-1300: Physical Side Channels
        // RTL cannot measure power, but we can check timing consistency.
        // ------------------------------------------------------------
        $display("\n[CWE-1300] Timing consistency for different keys");

        rst = 1; #10 rst = 0;

        // Measure cycles for push+pop of different keys (they will be constant)
        push_key(64'h0000000000000001);
        pop_key();

        push_key(64'hFFFFFFFFFFFFFFFF);
        pop_key();

        $display("Push/pop take fixed cycles, but no masking/blinding is implemented.");
        $display("Registers toggle directly with key bits → potential side-channel source.");

        $display("\n=== SECURITY TESTBENCH FOR secret_fifo END ===");
        #50 $finish;
    end

endmodule

