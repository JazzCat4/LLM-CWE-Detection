`timescale 1ns/1ps
`include "2.v"
module test_tb;

  // DUT inputs
  reg CLK;
  reg RST;
  reg enable;
  reg [31:0] value;

  // DUT output
  wire [7:0] led;

  // Instantiate DUT
  test dut (
    .CLK(CLK),
    .RST(RST),
    .enable(enable),
    .value(value),
    .led(led)
  );

  // Clock generation (normal + glitch injection)
  initial begin
    CLK = 0;
    forever #5 CLK = ~CLK;   // 100 MHz nominal clock
  end

  // Task: Inject a clock glitch (CWE‑1247)
  task inject_clock_glitch;
    begin
      #1 CLK = ~CLK;   // force an early edge
      #1 CLK = ~CLK;   // force another edge
    end
  endtask

  // Task: Print internal state (requires hierarchical access)
  task show_state;
    begin
      $display("TIME=%0t | state=%0d | count=%h | led=%h",
               $time, dut.state, dut.count, led);
    end
  endtask

  initial begin
    $display("=== CWE Vulnerability Testbench Start ===");

    // -------------------------------
    // 1. CWE‑226: Sensitive data not scrubbed
    // -------------------------------
    $display("\n[CWE‑226] Testing lack of scrubbing...");
    RST = 0; enable = 0; value = 32'hDEADBEEF;
    #20; show_state();

    RST = 1;  // release reset
    #20;

    // Drive FSM to update count with sensitive value
    enable = 1;
    #10 enable = 0;
    #50 show_state();

    // Now simulate a "context switch" without reset
    $display("[CWE‑226] Checking if sensitive count persists...");
    #50 show_state();   // count should still contain DEADBEEF + prior additions

    // -------------------------------
    // 2. CWE‑1256: Unprivileged access to hardware features
    // -------------------------------
    $display("\n[CWE‑1256] Testing unrestricted external control...");
    $display("Driving enable/value from untrusted source...");
    value = 32'h11111111;
    enable = 1;
    #10 enable = 0;
    #50 show_state();   // count updates without any privilege gating

    // -------------------------------
    // 3. CWE‑1247: Clock glitch vulnerability
    // -------------------------------
    $display("\n[CWE‑1247] Injecting clock glitch...");
    enable = 1;
    #10 enable = 0;

    inject_clock_glitch();   // glitch during FSM transition
    #20 show_state();

    // -------------------------------
    // 4. Illegal FSM state reachability (fault injection)
    // -------------------------------
    $display("\n[CWE‑1247] Forcing illegal FSM state...");
    dut.state = 8'hFF;   // simulate bit‑flip fault
    #10 show_state();
    #10 show_state();    // FSM should force state back to 0 but without error signaling

    // -------------------------------
    // 5. CWE‑1262: No access control on register interface
    // -------------------------------
    $display("\n[CWE‑1262] Testing read exposure of sensitive data...");
    $display("LED output leaks count[23:16]...");
    #20 show_state();

    $display("\n=== CWE Vulnerability Testbench Complete ===");
    $finish;
  end

endmodule
