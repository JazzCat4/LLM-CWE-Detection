
`timescale 1ns/1ps

module tb_test_secure;

    reg clk, rst, start, glitch_detect;
    reg [31:0] base, exponent;
    wire [31:0] result;
    wire done;

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

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal
    end

    initial begin
        $display("=== CWE Security Testbench (Hardened DUT) Start ===");

        glitch_detect = 0;
        rst   = 1;
        start = 0;
        base  = 32'd0;
        exponent = 32'd0;
        #12 rst = 0;

        // ------------------------------------------------------------
        // CWE-226: verify scrubbing across reset and reuse
        // ------------------------------------------------------------
        $display("\n[CWE-226] Scrub behavior across reset and reuse");

        base     = 32'hAAAA_BBBB;
        exponent = 32'h0000_0003;
        start    = 1; #10 start = 0;
        wait(done);
        $display("First result: %h", result);

        // Reset should scrub all internal registers
        rst = 1; #10 rst = 0;

        base     = 32'h1111_2222;
        exponent = 32'h0000_0002;
        start    = 1; #10 start = 0;
        wait(done);
        $display("Second result: %h", result);
        $display("Check waveforms: base_reg/exp_reg/res_reg should be 0 at IDLE and after DONE.");

        // ------------------------------------------------------------
        // CWE-1247: glitch detection and safe ERROR state
        // ------------------------------------------------------------
        $display("\n[CWE-1247] Glitch detection forcing ERROR state");

        rst = 1; #10 rst = 0;
        base     = 32'h0000_0002;
        exponent = 32'h0000_0008;
        start    = 1; #10 start = 0;

        // Assert glitch_detect during RUN
        #40 glitch_detect = 1;
        #10 glitch_detect = 0;

        // Allow some cycles to observe ERROR behavior
        repeat(20) @(posedge clk);
        $display("Check: state should be ERROR, result/done cleared, registers scrubbed.");

        // ------------------------------------------------------------
        // CWE-1300: constant-time behavior vs exponent pattern
        // ------------------------------------------------------------
        $display("\n[CWE-1300] Constant-time behavior check");

        rst = 1; #10 rst = 0;

        // Case 1: high Hamming weight exponent
        exponent = 32'hFFFF_FFFF;
        base     = 32'h0000_0002;
        start    = 1; #10 start = 0;

        time start_time;
        time end_time;

        start_time = $time;
        wait(done);
        end_time = $time;
        $display("High-HW exponent cycles: %0d", end_time - start_time);

        // Case 2: low Hamming weight exponent
        rst = 1; #10 rst = 0;
        exponent = 32'h0000_0001;
        base     = 32'h0000_0002;
        start    = 1; #10 start = 0;

        start_time = $time;
        wait(done);
        end_time = $time;
        $display("Low-HW exponent cycles: %0d", end_time - start_time);

        $display("Both cases should take the same number of cycles (constant-time loop).");

        $display("\n=== CWE Security Testbench (Hardened DUT) Complete ===");
        $finish;
    end

endmodule
