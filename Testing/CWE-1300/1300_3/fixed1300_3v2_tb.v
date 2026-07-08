`timescale 1ns/1ps

module tb_test_secure;

    reg clk, rst, start, glitch_detect;
    reg [31:0] base, exponent;
    wire [31:0] result;
    wire done;

    // Time variables must be declared at top
    time start_time;
    time end_time;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .glitch_detect(glitch_detect),
        .base(base),
        .exponent(exponent),
        .result(result),
        .done(done)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        $display("=== CWE Security Testbench Start ===");

        glitch_detect = 0;
        rst = 1;
        start = 0;
        base = 0;
        exponent = 0;
        #12 rst = 0;

        // ------------------------------------------------------------
        // CWE-226: Scrubbing test
        // ------------------------------------------------------------
        $display("\n[CWE-226] Testing scrubbing behavior");

        base = 32'hAAAA_BBBB;
        exponent = 32'h0000_0003;
        start = 1; #10 start = 0;
        wait(done);
        $display("First result: %h", result);

        rst = 1; #10 rst = 0;

        base = 32'h1111_2222;
        exponent = 32'h0000_0002;
        start = 1; #10 start = 0;
        wait(done);
        $display("Second result: %h", result);

        // ------------------------------------------------------------
        // CWE-1247: Glitch detection test
        // ------------------------------------------------------------
        $display("\n[CWE-1247] Testing glitch detection");

        rst = 1; #10 rst = 0;
        base = 32'h0000_0002;
        exponent = 32'h0000_0008;
        start = 1; #10 start = 0;

        #40 glitch_detect = 1;
        #10 glitch_detect = 0;

        repeat(20) @(posedge clk);
        $display("Check waveform: state should be ERROR.");

        // ------------------------------------------------------------
        // CWE-1300: Constant-time test
        // ------------------------------------------------------------
        $display("\n[CWE-1300] Testing constant-time behavior");

        rst = 1; #10 rst = 0;

        exponent = 32'hFFFF_FFFF;
        base = 32'h0000_0002;
        start = 1; #10 start = 0;

        start_time = $time;
        wait(done);
        end_time = $time;
        $display("High-HW cycles: %0d", end_time - start_time);

        rst = 1; #10 rst = 0;

        exponent = 32'h0000_0001;
        base = 32'h0000_0002;
        start = 1; #10 start = 0;

        start_time = $time;
        wait(done);
        end_time = $time;
        $display("Low-HW cycles: %0d", end_time - start_time);

        $display("Both should match (constant-time).");

        $display("\n=== CWE Security Testbench Complete ===");
        $finish;
    end

endmodule
