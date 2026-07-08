`timescale 1ns/1ps

module Ex1_secure_tb;

    reg clk;
    reg reset;

    reg        sw_we;
    reg [3:0]  sw_addr;
    reg [31:0] sw_wdata;
    reg        sw_privileged;

    wire [31:0] sw_rdata;
    wire        accel_enable;

    // DUT
    Ex1_secure dut (
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

    initial begin
        $display("=== Starting Secure Module Testbench ===");

        clk = 0;
        reset = 1;
        sw_we = 0;
        sw_addr = 0;
        sw_wdata = 0;
        sw_privileged = 0;

        #20 reset = 0;

        // ------------------------------------------------------------
        // CWE-1256 / CWE-1262: Unprivileged write should NOT enable accelerator
        // ------------------------------------------------------------
        $display("\n[TEST] Unprivileged write to CTRL must NOT enable accelerator");
        sw_privileged = 0;
        sw_we = 1;
        sw_addr = 4'h0; // ADDR_CTRL
        sw_wdata = 32'h1;
        #10 sw_we = 0;

        #10 $display("accel_enable = %0d (EXPECTED: 0)", accel_enable);

        // ------------------------------------------------------------
        // CWE-1262: Privileged write enables accelerator
        // ------------------------------------------------------------
        $display("\n[TEST] Privileged write to CTRL enables accelerator");
        sw_privileged = 1;
        sw_we = 1;
        sw_addr = 4'h0;
        sw_wdata = 32'h1;
        #10 sw_we = 0;

        #10 $display("accel_enable = %0d (EXPECTED: 1)", accel_enable);

        // ------------------------------------------------------------
        // CWE-226: Loss of privilege scrubs sensitive state
        // ------------------------------------------------------------
        $display("\n[TEST] Loss of privilege scrubs CTRL and disables accelerator");
        sw_privileged = 0;
        #10;
        $display("accel_enable after privilege drop = %0d (EXPECTED: 0)", accel_enable);

        // ------------------------------------------------------------
        // CWE-1262: Lock bit prevents further modification
        // ------------------------------------------------------------
        $display("\n[TEST] Locking CTRL prevents further writes");
        // Re-enable as privileged
        sw_privileged = 1;
        sw_we = 1;
        sw_addr = 4'h0;
        sw_wdata = 32'h1;
        #10 sw_we = 0;
        #10 $display("accel_enable before lock = %0d (EXPECTED: 1)", accel_enable);

        // Set lock
        sw_we = 1;
        sw_addr = 4'h1; // ADDR_LOCK
        sw_wdata = 32'h1;
        #10 sw_we = 0;

        // Try to change CTRL after lock
        sw_we = 1;
        sw_addr = 4'h0;
        sw_wdata = 32'h0;
        #10 sw_we = 0;

        #10 $display("accel_enable after locked write = %0d (EXPECTED: 1, unchanged)", accel_enable);

        // ------------------------------------------------------------
        // CWE-226: Reset scrubs sensitive state
        // ------------------------------------------------------------
        $display("\n[TEST] Reset scrubs CTRL and disables accelerator");
        reset = 1;
        #10 reset = 0;
        #10 $display("accel_enable after reset = %0d (EXPECTED: 0)", accel_enable);

        $display("\n=== Secure Module Testbench Complete ===");
        $finish;
    end

endmodule
