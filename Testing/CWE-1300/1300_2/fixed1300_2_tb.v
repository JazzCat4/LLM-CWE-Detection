`timescale 1ns/1ps

module tb_secure_test;

    reg         clk;
    reg         rst_n;
    reg         priv_en;
    reg         glitch_detect;
    reg  [7:0]  base_in;
    reg  [7:0]  secret_key_in;
    wire [15:0] result;
    wire        error;

    secure_test dut (
        .clk(clk),
        .rst_n(rst_n),
        .priv_en(priv_en),
        .glitch_detect(glitch_detect),
        .base_in(base_in),
        .secret_key_in(secret_key_in),
        .result(result),
        .error(error)
    );

    // clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    integer cycles_short;
    integer cycles_long;

    initial begin
        rst_n        = 0;
        priv_en      = 0;
        glitch_detect= 0;
        base_in      = 0;
        secret_key_in= 0;
        cycles_short = 0;
        cycles_long  = 0;

        #20 rst_n = 1;

        // CWE-226: reuse with scrubbing
        priv_en      = 1;
        secret_key_in= 8'hA5;
        base_in      = 8'h03;
        @(posedge clk); // start
        repeat(8) @(posedge clk);
        $display("[CWE-226] First result: %h", result);

        // start new operation; previous key/base should be scrubbed
        secret_key_in= 8'h5A;
        base_in      = 8'h07;
        @(posedge clk);
        repeat(8) @(posedge clk);
        $display("[CWE-226] Second result (after scrub): %h", result);

        // CWE-1247: glitch_detect forces error and scrub
        glitch_detect = 1;
        @(posedge clk);
        glitch_detect = 0;
        $display("[CWE-1247] After glitch_detect: error=%b, result=%h", error, result);

        // CWE-1256/1262: unprivileged access blocked
        priv_en       = 0;
        secret_key_in = 8'hFF;
        base_in       = 8'hFF;
        @(posedge clk);
        repeat(8) @(posedge clk);
        $display("[CWE-1256/1262] Unprivileged: result=%h (should not change meaningfully), error=%b", result, error);

        // CWE-1300: constant-time check (short vs long key)
        priv_en       = 1;
        secret_key_in = 8'h01; // short key
        base_in       = 8'h03;
        @(posedge clk);
        cycles_short = 0;
        while (dut.iter_cnt != 0) begin
            @(posedge clk);
            cycles_short = cycles_short + 1;
        end

        secret_key_in = 8'hF0; // long key
        base_in       = 8'h03;
        @(posedge clk);
        cycles_long = 0;
        while (dut.iter_cnt != 0) begin
            @(posedge clk);
            cycles_long = cycles_long + 1;
        end

        $display("[CWE-1300] cycles_short=%0d, cycles_long=%0d (should be equal)", 
                 cycles_short, cycles_long);

        $finish;
    end

endmodule
