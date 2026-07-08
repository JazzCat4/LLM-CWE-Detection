`include "2.v"

`timescale 1ns/1ps

module tb_test;

  reg CLK;
  reg RST;
  reg enable;
  reg [31:0] value;
  wire [7:0] led;

  // Instantiate DUT
  test dut (
    .CLK(CLK),
    .RST(RST),
    .enable(enable),
    .value(value),
    .led(led)
  );

  // Normal clock
  initial CLK = 0;
  always #5 CLK = ~CLK;   // 100 MHz nominal clock

  // Task: Inject a clock glitch (extra rising edge)
  task inject_clock_glitch;
    begin
      #1 CLK = 1;   // force unexpected edge
      #1 CLK = 0;
      $display(">>> CLOCK GLITCH INJECTED at time %t", $time);
    end
  endtask

  // Task: Inject a reset glitch (short pulse)
  task inject_reset_glitch;
    begin
      RST = 0;
      #2;
      RST = 1;
      $display(">>> RESET GLITCH INJECTED at time %t", $time);
    end
  endtask

  // Task: Corrupt FSM state (illegal state injection)
  task corrupt_fsm_state;
    begin
      dut.state = 8'hFF;   // illegal state
      $display(">>> FSM CORRUPTED to illegal state at time %t", $time);
    end
  endtask

  initial begin
    $display("=== CWE Vulnerability Testbench Start ===");

    // Initial conditions
    RST = 0;
    enable = 0;
    value = 32'h00000010;

    // Release reset
    #20 RST = 1;

    // Normal operation
    #20 enable = 1;
    #10 enable = 0;

    // Inject clock glitch during FSM transition
    #30 inject_clock_glitch();

    // Inject reset glitch during count update
    #40 inject_reset_glitch();

    // Corrupt FSM state to test illegal-state handling
    #50 corrupt_fsm_state();

    // Manipulate untrusted inputs
    #20 value = 32'hFFFFFFFF;
    enable = 1;

    #100 $display("=== CWE Vulnerability Testbench Complete ===");
    $finish;
  end

endmodule
