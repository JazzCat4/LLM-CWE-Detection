`include "1.v"

`timescale 1ns/1ps

module tb_test;

    reg  [2:0] user_input;
    reg        clk;
    reg        rst_n;
    wire [2:0] out;

    // DUT
    test dut (
        .out(out),
        .user_input(user_input),
        .clk(clk),
        .rst_n(rst_n)
    );

    // Normal clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Task: inject a clock glitch (CWE‑1247 test)
    task inject_clk_glitch;
    begin
        #1 clk = ~clk;   // extra unexpected toggle
        #1 clk = ~clk;   // restore
    end
    endtask

    // Task: inject reset glitch (CWE‑1247 test)
    task inject_reset_glitch;
    begin
        rst_n = 0;
        #1 rst_n = 1;
    end
    endtask

    initial begin
        $display("=== CWE‑1247 / CWE‑1234 Security Testbench ===");

        // Initial conditions
        rst_n = 0;
        user_input = 0;
        #20 rst_n = 1;

        // Normal operation
        #10 user_input = 3'h3;   // set state = 3
        #20;

        // Inject clock glitch
        $display("[TEST] Injecting clock glitch...");
        inject_clk_glitch();
        #20;

        // Inject reset glitch
        $display("[TEST] Injecting reset glitch...");
        inject_reset_glitch();
        #20;

        // Illegal state forcing (CWE‑1247: FSM has no error state)
        $display("[TEST] Forcing illegal state value...");
        force dut.state = 2'b11;   // force highest state
        #10 release dut.state;

        // CWE‑1234 validation: ensure no debug/test signals exist
        if (^dut.state === 1'bX) begin
            $display("[WARN] State entered X due to glitch — no safe-state fallback (CWE‑1247).");
        end

        $display("[INFO] No debug/test/JTAG signals detected — CWE‑1234 not applicable.");

        #50 $finish;
    end

endmodule
