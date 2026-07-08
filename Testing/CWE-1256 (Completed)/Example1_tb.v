`timescale 1ns/1ps

module Ex1_tb;

    reg clk;
    reg reset;

    reg sw_we;
    reg [3:0] sw_addr;
    reg [31:0] sw_wdata;
    reg sw_privileged;

    wire [31:0] sw_rdata;
    wire accel_enable;

    // DUT
    Ex1 dut (
        .clk(clk),
        .reset(reset),
        .sw_we(sw_we),
        .sw_addr(sw_addr),
        .sw_wdata(sw_wdata),
        .sw_rdata(sw_rdata),
        .sw_privileged(sw_privileged),
        .accel_enable(accel_enable)
    );

    // Clock
    always #5 clk = ~clk;

    // Test sequence
    initial begin
        $display("=== Starting Vulnerability Testbench ===");

        clk = 0;
        reset = 1;
        sw_we = 0;
        sw_addr = 0;
        sw_wdata = 0;
        sw_privileged = 0;

        #20 reset = 0;

        // ------------------------------------------------------------
        // CWE-1256 / CWE-1262: Unprivileged software enables accelerator
        // ------------------------------------------------------------
        $display("\n[TEST] Unprivileged write to privileged accelerator control");
        sw_privileged = 0; // attacker is unprivileged
        sw_we = 1;
        sw_addr = 4'h0; // ADDR_CTRL
        sw_wdata = 32'h1; // enable accelerator
        #10 sw_we = 0;

        #10 $display("accel_enable = %0d (EXPECTED: 1, demonstrates vulnerability)", accel_enable);

        // ------------------------------------------------------------
        // CWE-1262: Privilege bit ignored
        // ------------------------------------------------------------
        $display("\n[TEST] Privileged vs unprivileged writes behave identically");
        sw_privileged = 1; // privileged
        sw_we = 1;
        sw_wdata = 32'h0; // disable accelerator
        #10 sw_we = 0;

        #10 $display("accel_enable = %0d (EXPECTED: 0, but privileged/unprivileged treated same)", accel_enable);

        // ------------------------------------------------------------
        // CWE-226: Sensitive configuration persists across contexts
        // ------------------------------------------------------------
        $display("\n[TEST] Sensitive register persists across context switch");
        sw_privileged = 0; // attacker context
        sw_we = 1;
        sw_wdata = 32'h1; // enable accelerator again
        #10 sw_we = 0;

        #10 $display("accel_enable before context switch = %0d", accel_enable);

        // Simulate context switch: privileged software takes over
        sw_privileged = 1;
        $display("accel_enable after context switch = %0d (EXPECTED: still 1, demonstrates persistence)", accel_enable);

        // ------------------------------------------------------------
        // CWE-226: Reset is only scrub mechanism
        // ------------------------------------------------------------
        $display("\n[TEST] Reset clears sensitive register (only scrub path)");
        reset = 1;
        #10 reset = 0;

        #10 $display("accel_enable after reset = %0d (EXPECTED: 0)", accel_enable);

        // ------------------------------------------------------------
        // CWE-1300: No crypto datapath to test constant-time behavior
        // ------------------------------------------------------------
        $display("\n[TEST] No crypto datapath present; CWE-1300 not applicable to this module");

        $display("\n=== Vulnerability Testbench Complete ===");
        $finish;
    end

endmodule