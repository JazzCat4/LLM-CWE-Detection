`timescale 1ns/1ps
`include "fixed.v"
module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         glitch_detect;
    reg  [1:0]  secret_mode;
    reg  [15:0] data_in;
    reg         scrub;
    wire [15:0] acc;
    wire        error;

    // Instantiate hardened DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .glitch_detect(glitch_detect),
        .secret_mode(secret_mode),
        .data_in(data_in),
        .scrub(scrub),
        .acc(acc),
        .error(error)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Tasks reused conceptually from previous TB

    // Clock glitch (still injected to show that glitch_detect can override)
    task inject_clock_glitch;
        begin
            #1 clk = 1;
            #1 clk = 0;
            $display("[GLITCH] Clock glitch injected at time %t", $time);
        end
    endtask

    // Reset glitch
    task inject_reset_glitch;
        begin
            rst_n = 0;
            #1 rst_n = 1;
            $display("[GLITCH] Reset glitch injected at time %t", $time);
        end
    endtask

    // Side-channel probe (logical behavior; physical side-channel mitigated by constant-time datapath)
    task side_channel_probe(input [1:0] mode, input [15:0] din);
        begin
            secret_mode   = mode;
            data_in       = din;
            glitch_detect = 0;
            scrub         = 0;
            @(posedge clk);
            $display("[SC] secret_mode=%b data_in=%0d acc=%0d error=%0b", mode, din, acc, error);
        end
    endtask

    // Scrub check
    task check_scrub;
        begin
            @(negedge clk);
            if (acc !== 16'd0)
                $display("[SCRUB FAIL] acc not cleared after scrub/reset! acc=%0d", acc);
            else
                $display("[SCRUB PASS] acc cleared correctly.");
        end
    endtask

    initial begin
        $display("=== Hardened Security Validation Testbench Start ===");

        rst_n        = 0;
        glitch_detect= 0;
        secret_mode  = 2'b01;
        data_in      = 0;
        scrub        = 0;

        // Release reset
        #20 rst_n = 1;

        // ------------------------------------------------------------
        // CWE-1300: Side-channel logical behavior test
        // (both add/sub paths computed every cycle)
        // ------------------------------------------------------------
        $display("\n=== CWE-1300: Side-Channel Logical Test ===");
        side_channel_probe(2'b01, 16'd5);    // add
        side_channel_probe(2'b10, 16'd5);    // sub
        side_channel_probe(2'b01, 16'd100);  // add
        side_channel_probe(2'b10, 16'd100);  // sub

        // Invalid encoding → error state
        side_channel_probe(2'b11, 16'd7);

        // ------------------------------------------------------------
        // CWE-1247: Glitch detection / safe state test
        // ------------------------------------------------------------
        $display("\n=== CWE-1247: Glitch Detection Test ===");
        secret_mode   = 2'b01;
        data_in       = 16'd7;
        glitch_detect = 0;
        @(posedge clk);
        inject_clock_glitch;
        glitch_detect = 1;  // sensor reports glitch
        @(posedge clk);
        $display("[POST-GLITCH] acc=%0d error=%0b (should be safe error state)", acc, error);
        glitch_detect = 0;

        // Reset glitch with glitch_detect asserted
        secret_mode   = 2'b10;
        data_in       = 16'd3;
        @(posedge clk);
        inject_reset_glitch;
        glitch_detect = 1;
        @(posedge clk);
        $display("[POST-RESET-GLITCH] acc=%0d error=%0b (should be safe error state)", acc, error);
        glitch_detect = 0;

        // ------------------------------------------------------------
        // CWE-226: Scrubbing test
        // ------------------------------------------------------------
        $display("\n=== CWE-226: Scrubbing Test ===");
        secret_mode = 2'b01;
        data_in     = 16'd50;
        @(posedge clk);
        @(posedge clk);
        $display("[PRE-SCRUB] acc=%0d (secret-derived)", acc);

        // Explicit scrub
        scrub = 1;
        @(posedge clk);
        scrub = 0;
        check_scrub;

        // Final reset check
        rst_n = 0;
        @(posedge clk);
        rst_n = 1;
        check_scrub;

        #50;
        $display("\n=== Hardened Security Validation Testbench Complete ===");
        $finish;
    end

endmodule
