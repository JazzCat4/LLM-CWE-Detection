`timescale 1ns/1ps
`include "5.v"
module tb_test3_security_monitor;

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

    // Print DUT state every cycle
    always @(posedge clk) begin
        $display("TIME=%0t | clk=%b rst_n=%b start=%b | stage=%b | done=%b",
                 $time, clk, rst_n, start, dut.stage, done);
    end

    // Inject a clock glitch
    task inject_clock_glitch;
        begin
            $display("---- Injecting CLOCK GLITCH at %0t ----", $time);
            #1 clk = 1;
            #1 clk = 0;
            #1 clk = 1;
        end
    endtask

    // Inject a reset glitch
    task inject_reset_glitch;
        begin
            $display("---- Injecting RESET GLITCH at %0t ----", $time);
            rst_n = 0;
            #1 rst_n = 1;
        end
    endtask

    // Corrupt FSM state
    task corrupt_fsm_state;
        begin
            $display("---- Corrupting FSM STATE at %0t ----", $time);
            force dut.stage = 2'bxx;
            #10 release dut.stage;
        end
    endtask

    // Glitch start signal
    task glitch_start;
        begin
            $display("---- Glitching START SIGNAL at %0t ----", $time);
            start = 1;
            #1 start = 0;
            #1 start = 1;
            #1 start = 0;
        end
    endtask

    // Task: Start the FSM cleanly
    task start_fsm;
        begin
            $display("---- Starting FSM at %0t ----", $time);
            start = 1;
            #10 start = 0;
        end
    endtask

    // Main stimulus
    initial begin
        $display("=== Starting DUT State Monitor Testbench ===");

        // Initial reset
        rst_n = 0;
        start = 0;
        #20 rst_n = 1;

        // ---------------------------------------------------------
        // Test 1: Normal operation
        // ---------------------------------------------------------
        $display("\n===== TEST 1: Normal FSM Operation =====");
        start_fsm;
        #80;

        // ---------------------------------------------------------
        // Test 2: Clock glitch after FSM start
        // ---------------------------------------------------------
        $display("\n===== TEST 2: Clock Glitch =====");
        start_fsm;
        #30 inject_clock_glitch;
        #80;

        // ---------------------------------------------------------
        // Test 3: Reset glitch after FSM start
        // ---------------------------------------------------------
        $display("\n===== TEST 3: Reset Glitch =====");
        start_fsm;
        #30 inject_reset_glitch;
        #80;

        // ---------------------------------------------------------
        // Test 4: Illegal FSM state corruption
        // ---------------------------------------------------------
        $display("\n===== TEST 4: Illegal FSM State Corruption =====");
        start_fsm;
        #30 corrupt_fsm_state;
        #80;

        // ---------------------------------------------------------
        // Test 5: Start signal glitching
        // ---------------------------------------------------------
        $display("\n===== TEST 5: Start Signal Glitch =====");
        start_fsm;
        #30 glitch_start;
        #80;

        $display("\n=== Testbench Complete ===");
        $finish;
    end

endmodule
