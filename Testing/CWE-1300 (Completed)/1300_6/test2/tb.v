`include "1300_6.v"

`timescale 1ns/1ps

module tb_test;

    reg         clk;
    reg         rst_n;
    reg         secret_bit;
    reg  [15:0] data_in;
    wire [15:0] acc;

    // Instantiate DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .secret_bit(secret_bit),
        .data_in(data_in),
        .acc(acc)
    );

    // Clock generation (normal)
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal clock
    end

    // --- TASKS --------------------------------------------------------------

    // CWE‑1247: Inject a clock glitch (extra pulse)
    task inject_clock_glitch;
        begin
            #1 clk = 1;
            #1 clk = 0;
            $display("[GLITCH] Clock glitch injected at time %t", $time);
        end
    endtask

    // CWE‑1247: Inject reset glitch (brief reset pulse)
    task inject_reset_glitch;
        begin
            rst_n = 0;
            #1 rst_n = 1;
            $display("[GLITCH] Reset glitch injected at time %t", $time);
        end
    endtask

    // CWE‑1300: Toggle secret_bit and observe power/timing‑correlated behavior
    task side_channel_probe(input sb, input [15:0] din);
        begin
            secret_bit = sb;
            data_in    = din;
            @(posedge clk);
            $display("[SC] secret_bit=%0d data_in=%0d acc=%0d", sb, din, acc);
        end
    endtask

    // CWE‑226: Check whether acc is scrubbed after reset
    task check_scrub;
        begin
            @(negedge clk);
            if (acc !== 16'd0)
                $display("[SCRUB FAIL] acc not cleared after reset! acc=%0d", acc);
            else
                $display("[SCRUB PASS] acc cleared correctly.");
        end
    endtask

    // --- TEST SEQUENCE ------------------------------------------------------

    initial begin
        $display("=== Security Validation Testbench Start ===");

        // Initial conditions
        rst_n      = 0;
        secret_bit = 0;
        data_in    = 0;

        // Release reset
        #20 rst_n = 1;

        // ------------------------------------------------------------
        // CWE‑1300: Side‑channel leakage test
        // ------------------------------------------------------------
        $display("\n=== CWE‑1300: Side‑Channel Leakage Test ===");
        side_channel_probe(1'b0, 16'd5);   // subtraction path
        side_channel_probe(1'b1, 16'd5);   // addition path
        side_channel_probe(1'b0, 16'd100);
        side_channel_probe(1'b1, 16'd100);

        // ------------------------------------------------------------
        // CWE‑1247: Clock glitch injection
        // ------------------------------------------------------------
        $display("\n=== CWE‑1247: Clock Glitch Injection Test ===");
        secret_bit = 1;
        data_in    = 16'd7;
        @(posedge clk);
        inject_clock_glitch;   // extra pulse → unexpected update
        @(posedge clk);
        $display("[POST-GLITCH] acc=%0d", acc);

        // ------------------------------------------------------------
        // CWE‑1247: Reset glitch injection
        // ------------------------------------------------------------
        $display("\n=== CWE‑1247: Reset Glitch Injection Test ===");
        secret_bit = 0;
        data_in    = 16'd3;
        @(posedge clk);
        inject_reset_glitch;   // brief reset → partial/incorrect clearing
        @(posedge clk);
        $display("[POST-RESET-GLITCH] acc=%0d", acc);

        // ------------------------------------------------------------
        // CWE‑226: Scrubbing validation
        // ------------------------------------------------------------
        $display("\n=== CWE‑226: Scrubbing Test ===");
        secret_bit = 1;
        data_in    = 16'd50;
        @(posedge clk);
        @(posedge clk);
        $display("[PRE-RESET] acc=%0d (should contain secret-derived data)", acc);

        // Apply proper reset
        rst_n = 0;
        @(posedge clk);
        check_scrub;   // verify acc is cleared

        rst_n = 1;

        // End
        #50;
        $display("\n=== Security Validation Testbench Complete ===");
        $finish;
    end

endmodule
