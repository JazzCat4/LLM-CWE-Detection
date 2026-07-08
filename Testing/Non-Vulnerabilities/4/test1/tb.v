`timescale 1ns/1ps
`include "4.v"
module tb_test2;

    reg clk;
    reg rst_n;
    reg [1:0] in;
    wire detect;

    // DUT
    test2 dut (
        .clk(clk),
        .rst_n(rst_n),
        .in(in),
        .detect(detect)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal
    end

    // === State Monitor ===
    // Prints internal DUT state every clock edge
    always @(posedge clk) begin
        $display("[%0t] clk↑  rst_n=%b  in=%b  shift_reg=%b  detect=%b",
                 $time, rst_n, in, dut.shift_reg, detect);
    end

    // === Tasks ===

    // Inject a clock glitch
    task inject_clock_glitch;
        begin
            $display("\n=== Injecting CLOCK GLITCH at %0t ===", $time);
            #1 clk = ~clk;   // early edge
            #1 clk = ~clk;   // second edge
        end
    endtask

    // Inject a reset glitch
    task inject_reset_glitch;
        begin
            $display("\n=== Injecting RESET GLITCH at %0t ===", $time);
            rst_n = 0;
            #1;
            rst_n = 1;
        end
    endtask

    // Spoof debug/test mode (negative test for CWE‑1234)
    task spoof_debug_mode;
        begin
            $display("\n=== Spoofing DEBUG/TEST MODE at %0t ===", $time);
            $display("Note: DUT has no debug/test/lock bits — CWE‑1234 negative test.");
        end
    endtask

    // Force illegal FSM state
    task force_illegal_state;
        begin
            $display("\n=== Forcing ILLEGAL FSM STATE at %0t ===", $time);
            force dut.shift_reg = 3'b111;
            #10;
            release dut.shift_reg;
        end
    endtask

    // === Test Sequence ===
    initial begin
        $display("=== CWE‑1234 / CWE‑1247 Vulnerability Testbench Start ===");

        // Initial reset
        rst_n = 0;
        in = 2'b00;
        #20;
        rst_n = 1;

        // Normal operation
        in[0] = 1; #10;
        in[0] = 0; #10;
        in[0] = 1; #10;

        // CWE‑1247: Clock glitch
        inject_clock_glitch();
        #20;

        // CWE‑1247: Reset glitch
        inject_reset_glitch();
        #20;

        // CWE‑1247: Illegal FSM state
        force_illegal_state();
        #20;

        // CWE‑1234: Debug/test spoofing
        spoof_debug_mode();
        #20;

        // Additional input toggles
        in[0] = 1; #10;
        in[0] = 1; #10;
        in[0] = 0; #10;

        $display("=== Testbench Complete ===");
        $finish;
    end

endmodule
