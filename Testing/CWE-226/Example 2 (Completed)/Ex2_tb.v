`timescale 1ns/1ps
module tb_test_security;

  reg clk;
  reg rst_n;
  reg load_key;
  reg [127:0] key_in;
  wire [127:0] key_reg;

  // DUT
  test dut (
    .clk(clk),
    .rst_n(rst_n),
    .key_in(key_in),
    .load_key(load_key),
    .key_reg(key_reg)
  );

  // Clock generation
  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  initial begin
    $display("=== SECURITY TESTBENCH START ===");

    // -------------------------------
    // CWE-226: Sensitive data not scrubbed before reuse
    // -------------------------------
    rst_n = 0; load_key = 0; key_in = 0;
    #20;

    rst_n = 1;
    #10;

    // Load first key
    key_in = 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222;
    load_key = 1;
    #10 load_key = 0;

    $display("[CWE-226] First key loaded: %h", key_reg);

    // Load second key WITHOUT SCRUBBING
    key_in = 128'h1234_5678_9ABC_DEF0_1357_9BDF_2468_ACED;
    load_key = 1;
    #10 load_key = 0;

    $display("[CWE-226] Second key loaded (old key overwritten without zeroization): %h", key_reg);

    // -------------------------------
    // CWE-1262: No read access control
    // -------------------------------
    $display("[CWE-1262] Key is fully readable by ANY logic: %h", key_reg);

    // -------------------------------
    // CWE-1256: No privilege gating on key load
    // Simulate unprivileged software toggling load_key
    // -------------------------------
    $display("[CWE-1256] Simulating unprivileged write to load_key...");

    load_key = 1;
    key_in = 128'hBAD0_BAD0_BAD0_BAD0_BAD0_BAD0_BAD0_BAD0;
    #10 load_key = 0;

    $display("[CWE-1256] Unprivileged overwrite succeeded: %h", key_reg);

    // -------------------------------
    // CWE-226: Reset scrubbing validation
    // -------------------------------
    $display("[CWE-226] Asserting reset to check scrubbing...");
    rst_n = 0;
    #10;

    $display("[CWE-226] Key after reset (should be zero): %h", key_reg);

    rst_n = 1;
    #10;

    $display("=== SECURITY TESTBENCH END ===");
    $finish;
  end

endmodule
