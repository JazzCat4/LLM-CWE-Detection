`include "fixed.v"

`timescale 1ns/1ps

module tb_test_secure;

  // DUT inputs
  reg  [15:0] Data_in;
  reg         Clk;
  reg         rstn;
  reg         write;
  reg         Lock;
  reg         scan_mode;
  reg         debug_unlocked;
  reg         glitch_detect;

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
    .glitch_detect (glitch_detect),
    .Data_out      (Data_out)
  );

  // Clock generation
  initial Clk = 0;
  always #5 Clk = ~Clk;

  initial begin
    // Default inputs
    Data_in        = 16'h0000;
    write          = 1'b0;
    Lock           = 1'b0;
    scan_mode      = 1'b0;
    debug_unlocked = 1'b0;
    glitch_detect  = 1'b0;

    // 1) Global reset
    rstn = 0;
    #20;
    rstn = 1;
    #20;
    $display("After reset: Data_out=%h (expect 0000)", Data_out);

    // 2) Normal write when unlocked
    Data_in = 16'hA5A5;
    write   = 1'b1;
    #10;
    write   = 1'b0;
    #10;
    $display("Normal write unlocked: Data_out=%h (expect A5A5)", Data_out);

    // 3) Set lock and verify normal write blocked
    Lock = 1'b1;
    #10;
    Lock = 1'b0;
    #10;
    $display("After lock set: Data_out=%h (expect 0000 due to scrub on lock)", Data_out);

    Data_in = 16'h5A5A;
    write   = 1'b1;
    #10;
    write   = 1'b0;
    #10;
    $display("Write while locked (no debug): Data_out=%h (expect still 0000)", Data_out);

    // 4) Debug/test signals no longer override lock
    Data_in   = 16'hDEAD;
    write     = 1'b1;
    scan_mode = 1'b1;
    debug_unlocked = 1'b1;
    #10;
    write          = 1'b0;
    scan_mode      = 1'b0;
    debug_unlocked = 1'b0;
    #10;
    $display("Write while locked with scan_mode/debug_unlocked: Data_out=%h (expect still 0000, lock NOT overridden)", Data_out);

    // 5) Reset clears data, lock remains set-only until next power-on
    rstn = 0;
    #10;
    rstn = 1;
    #20;
    $display("After reset: Data_out=%h (expect 0000)", Data_out);

    // 6) Glitch detection forces safe state
    Data_in = 16'h1234;
    write   = 1'b1;
    #10;
    write   = 1'b0;
    #10;
    $display("Write unlocked before glitch: Data_out=%h (expect 1234)", Data_out);

    glitch_detect = 1'b1;
    #10;
    glitch_detect = 1'b0;
    #10;
    $display("After glitch_detect pulse: Data_out=%h (expect 0000, forced safe state)", Data_out);

    $display("SECURE TESTBENCH COMPLETE");
    $finish;
  end

endmodule
