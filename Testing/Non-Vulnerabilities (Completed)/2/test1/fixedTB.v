`timescale 1ns/1ps
`include "fixed.v"
module tb_test_secure;

  reg CLK;
  reg RST;
  reg enable;
  reg [31:0] value;
  reg glitch_detect;
  wire [7:0] led;

  // Instantiate hardened DUT
  test_secure dut (
    .CLK(CLK),
    .RST(RST),
    .enable(enable),
    .value(value),
    .glitch_detect(glitch_detect),
    .led(led)
  );

  // Normal clock
  initial CLK = 0;
  always #5 CLK = ~CLK;   // 100 MHz nominal clock

  // Task: Inject a clock glitch (extra rising edge)
  task inject_clock_glitch;
    begin
      #1 CLK = 1;
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
      dut.state = 2'b11;   // try to force ERROR or illegal
      $display(">>> FSM CORRUPTED at time %t", $time);
    end
  endtask

  initial begin
    $display("=== Hardened CWE Testbench Start ===");

    // Initial conditions
    RST = 0;
    enable = 0;
    value = 32'h00000010;
    glitch_detect = 0;

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

    // Assert glitch_detect to force ERROR state
    #20 glitch_detect = 1;
    #10 glitch_detect = 0;

    // Manipulate untrusted inputs
    #20 value = 32'hFFFFFFFF;
    enable = 1;

    #100 $display("=== Hardened CWE Testbench Complete ===");
    $finish;
  end

endmodule
