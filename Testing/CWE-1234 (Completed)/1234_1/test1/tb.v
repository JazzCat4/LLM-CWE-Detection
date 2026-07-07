`include "1234_1.v"

`timescale 1ns/1ps

module tb_test;

  // DUT inputs
  reg  [15:0] Data_in;
  reg         Clk;
  reg         rstn;
  reg         write;
  reg         Lock;
  reg         scan_mode;
  reg         debug_unlocked;

  // DUT output
  wire [15:0] Data_out;

  // Instantiate DUT
  test dut (
    .Data_in       (Data_in),
    .Clk           (Clk),
    .rstn          (rstn),
    .write         (write),
    .Lock          (Lock),
    .scan_mode     (scan_mode),
    .debug_unlocked(debug_unlocked),
    .Data_out      (Data_out)
  );

  // Clock generation
  initial Clk = 0;
  always #5 Clk = ~Clk; // 100 MHz

  // Testbench main sequence
  initial begin
    // Default inputs
    Data_in        = 16'h0000;
    write          = 1'b0;
    Lock           = 1'b0;
    scan_mode      = 1'b0;
    debug_unlocked = 1'b0;

    // -------------------------------
    // 1) Global reset (CWE-226, 1247)
    // -------------------------------
    rstn = 0;
    #20;
    rstn = 1;
    #20;
    $display("After reset: Data_out=%h (expect 0000), lock_status should be 0", Data_out);

    // -----------------------------------------
    // 2) Normal write when unlocked (baseline)
    // -----------------------------------------
    Data_in = 16'hA5A5;
    write   = 1'b1;
    #10; // one clock edge
    write   = 1'b0;
    #10;
    $display("Normal write unlocked: Data_out=%h (expect A5A5)", Data_out);

    // -----------------------------------------
    // 3) Set lock and verify normal write block
    //    (CWE-1262: lock used in normal path)
    // -----------------------------------------
    Lock = 1'b1;
    #10; // lock_status should become 1
    Lock = 1'b0;
    #10;

    Data_in = 16'h5A5A;
    write   = 1'b1;
    #10;
    write   = 1'b0;
    #10;
    $display("Write while locked (no debug): Data_out=%h (expect still A5A5)", Data_out);

    // -------------------------------------------------------
    // 4) CWE-1234 / 1191 / 1262 / 1256:
    //    Debug/test signals override lock and allow write
    // -------------------------------------------------------
    Data_in   = 16'hDEAD;
    write     = 1'b1;
    scan_mode = 1'b1;      // debug/test mode asserted
    #10;
    write     = 1'b0;
    scan_mode = 1'b0;
    #10;
    $display("Write while locked with scan_mode=1: Data_out=%h (expect DEAD) -> LOCK OVERRIDDEN", Data_out);

    Data_in        = 16'hBEEF;
    write          = 1'b1;
    debug_unlocked = 1'b1; // debug auth asserted
    #10;
    write          = 1'b0;
    debug_unlocked = 1'b0;
    #10;
    $display("Write while locked with debug_unlocked=1: Data_out=%h (expect BEEF) -> LOCK OVERRIDDEN", Data_out);

    // -------------------------------------------------------
    // 5) CWE-226: Sensitive data not scrubbed on context change
    //    - Data_out holds BEEF across lock/debug transitions
    // -------------------------------------------------------
    $display("Before any scrub: Data_out=%h (expect BEEF, still present across contexts)", Data_out);

    // Simulate context change: lock/unlock, debug off, no reset
    Lock = 1'b0; // unlock
    #10;
    Lock = 1'b1; // lock again
    #10;
    $display("After lock/unlock transitions: Data_out=%h (expect still BEEF, no scrub)", Data_out);

    // -------------------------------------------------------
    // 6) CWE-1234: Reset clears lock bit, re-enabling writes
    // -------------------------------------------------------
    rstn = 0;
    #10;
    rstn = 1;
    #20;
    $display("After reset: Data_out=%h (expect 0000), lock_status cleared -> lock removed", Data_out);

    // Write immediately after reset (lock cleared)
    Data_in = 16'hC0DE;
    write   = 1'b1;
    #10;
    write   = 1'b0;
    #10;
    $display("Write after reset (lock cleared): Data_out=%h (expect C0DE)", Data_out);

    // -------------------------------------------------------
    // 7) CWE-1247: Simple clock/reset glitch scenario
    //    (No glitch detection present)
    // -------------------------------------------------------
    // Simulate brief reset glitch during operation
    Data_in = 16'h1234;
    write   = 1'b1;
    #5;     // half cycle
    rstn   = 0; // glitch reset
    #5;
    rstn   = 1;
    #10;
    write   = 1'b0;
    #10;
    $display("After reset glitch: Data_out=%h (behavior may be inconsistent, no glitch protection)", Data_out);

    $display("TESTBENCH COMPLETE");
    $finish;
  end

endmodule
