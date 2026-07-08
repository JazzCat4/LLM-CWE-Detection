`timescale 1ns/1ps
`include "fixed.v"

module tb_test_secure;

    reg  clk;
    reg  rst_n;
    reg  glitch_err;
    reg  [2:0] usr_id;
    reg  [7:0] data_in;
    wire [7:0] data_out;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .usr_id(usr_id),
        .data_in(data_in),
        .glitch_err(glitch_err),
        .data_out(data_out)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    task inject_clock_glitch;
        begin
            #1 clk = ~clk;
            #1 clk = ~clk;
        end
    endtask

    task glitch_reset;
        begin
            rst_n = 0;
            #1 rst_n = 1;
        end
    endtask

    initial begin
        $display("=== Secure Testbench Start ===");

        rst_n      = 0;
        glitch_err = 0;
        usr_id     = 0;
        data_in    = 8'hAA;

        // Release reset
        #20 rst_n = 1;

        // T1: Normal privileged write
        $display("[T1] Normal privileged write");
        usr_id  = 3'h4;
        data_in = 8'h55;
        #10;
        $display("data_out = %h (expected 55)", data_out);

        // T2: Normal unprivileged write blocked
        $display("[T2] Normal unprivileged write");
        usr_id  = 3'h2;
        data_in = 8'h99;
        #10;
        $display("data_out = %h (expected 55)", data_out);

        // T3: Clock glitch attempt (should NOT bypass)
        $display("[T3] Injecting clock glitch to bypass privilege check");
        usr_id  = 3'h2;
        data_in = 8'hF0;
        #3 inject_clock_glitch;
        #10;
        $display("data_out = %h (should remain 55, no bypass)", data_out);

        // T4: Reset glitch (should force safe state)
        $display("[T4] Reset glitch attack");
        usr_id  = 3'h4;
        data_in = 8'hA5;
        #10;
        glitch_reset;
        #10;
        $display("data_out = %h (should be 00 after reset glitch)", data_out);

        // T6: Glitch error input (CWE-1247 mitigation)
        $display("[T6] Glitch error input forces safe state");
        usr_id     = 3'h4;
        data_in    = 8'h77;
        glitch_err = 1'b1;
        #10;
        $display("data_out = %h (should be 00 due to glitch_err)", data_out);
        glitch_err = 0;

        $display("=== Secure Testbench Complete ===");
        #20 $finish;
    end

endmodule
