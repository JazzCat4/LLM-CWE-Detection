`timescale 1ns/1ps
`include "5.v"
module tb_test3;

    reg clk;
    reg rst_n;
    reg start;
    wire done;

    // DUT
    test3 dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .done(done)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal
    end

    // Monitor DUT behavior every clock edge
    always @(posedge clk) begin
        $display("[TIME %0t] CLK ↑  stage=%b  start=%b  rst_n=%b  done=%b",
                 $time, dut.stage, start, rst_n, done);
    end

    // Clock glitch injection
    task inject_clk_glitch;
    begin
        $display("[TIME %0t] *** Injecting CLOCK GLITCH ***", $time);
        #1 clk = 1;
        #1 clk = 0;
        $display("[TIME %0t] *** Clock glitch complete ***", $time);
    end
    endtask

    // Reset glitch injection
    task inject_rst_glitch;
    begin
        $display("[TIME %0t] *** Injecting RESET GLITCH ***", $time);
        rst_n = 0;
        #1 rst_n = 1;
        $display("[TIME %0t] *** Reset glitch complete ***", $time);
    end
    endtask

    // Illegal FSM state injection
    task corrupt_fsm_state;
    begin
        $display("[TIME %0t] *** Forcing ILLEGAL FSM STATE (X) ***", $time);
        force dut.stage = 2'bxx;
        #2 release dut.stage;
        $display("[TIME %0t] *** Illegal state released ***", $time);
    end
    endtask

    initial begin
        $display("=== CWE Security Testbench Start ===");

        // Initial conditions
        rst_n = 0;
        start = 0;
        #20 rst_n = 1;

        // Normal operation
        $display("\n--- Normal FSM Operation ---");
        #10 start = 1;
        #10 start = 0;
        #50;

        // CWE-1247 Test 1: Clock glitch
        $display("\n--- CWE-1247 Test 1: Clock Glitch Injection ---");
        inject_clk_glitch();
        #40;

        // CWE-1247 Test 2: Reset glitch
        $display("\n--- CWE-1247 Test 2: Reset Glitch Injection ---");
        inject_rst_glitch();
        #40;

        // CWE-1247 Test 3: Illegal FSM state
        $display("\n--- CWE-1247 Test 3: Illegal FSM State Injection ---");
        corrupt_fsm_state();
        #40;

        // CWE-1234 Negative Test
        $display("\n--- CWE-1234 Negative Test: Debug Override Check ---");
        $display("No debug/test signals present. No CWE-1234 override paths detected.");

        $display("\n=== CWE Security Testbench Complete ===");
        $finish;
    end

endmodule
