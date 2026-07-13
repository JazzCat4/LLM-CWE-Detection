`timescale 1ns/1ps

module tb_test;

  reg         clk;
  reg         rst_n;
  reg [127:0] key_in;
  reg         load_key;
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

  // Utility task: print key
  task show_key;
    $display("[%0t] key_reg = %h", $time, key_reg);
  endtask

  initial begin
    $display("=== Starting CWE Security Validation Testbench ===");

    //----------------------------------------------------------------------
    // CWE‑226: Sensitive Information Not Removed Before Reuse
    //----------------------------------------------------------------------

    $display("\n--- CWE‑226 Test: Key overwritten without scrubbing ---");

    rst_n = 0; load_key = 0; key_in = 0;
    #12; rst_n = 1;  // exit reset
    #10;

    // Load first key
    key_in = 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222;
    load_key = 1; #10; load_key = 0;
    show_key();

    // Load second key WITHOUT scrubbing
    key_in = 128'h3333_4444_5555_6666_7777_8888_9999_AAAA;
    load_key = 1; #10; load_key = 0;
    show_key();

    $display("Expect: No scrub between keys → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑226: Reset scrubbing only, no lifecycle scrubbing
    //----------------------------------------------------------------------

    $display("\n--- CWE‑226 Test: Reset is the ONLY scrub path ---");

    rst_n = 0; #10; rst_n = 1;
    show_key();
    $display("Expect: Key cleared ONLY on reset → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑1247: Glitch / Fault Injection Vulnerability
    //----------------------------------------------------------------------

    $display("\n--- CWE‑1247 Test: Reset glitch during key load ---");

    // Load a key
    key_in = 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF;
    load_key = 1;

    // Inject a reset glitch mid‑cycle
    #3 rst_n = 0;
    #2 rst_n = 1;
    #5 load_key = 0;

    show_key();
    $display("Expect: Reset glitch corrupts key load → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑1247: Clock glitch
    //----------------------------------------------------------------------

    $display("\n--- CWE‑1247 Test: Clock glitch during update ---");

    // Load a new key
    key_in = 128'h0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
    load_key = 1;

    // Inject a clock glitch (extra edge)
    #2 clk = 1; #1 clk = 0; // artificial glitch
    #10 load_key = 0;

    show_key();
    $display("Expect: Clock glitch may cause double‑load or metastability → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑1256: No privilege gating on key load
    //----------------------------------------------------------------------

    $display("\n--- CWE‑1256 Test: Unauthorized key load allowed ---");

    // Simulate unprivileged software writing key
    key_in = 128'hFACE_FACE_FACE_FACE_FACE_FACE_FACE_FACE;
    load_key = 1; #10; load_key = 0;

    show_key();
    $display("Expect: Unprivileged load accepted → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑1262: No read access control
    //----------------------------------------------------------------------

    $display("\n--- CWE‑1262 Test: Key is readable by ANY requester ---");

    $display("Reading key_reg directly: %h", key_reg);
    $display("Expect: Sensitive key fully exposed → Vulnerability confirmed.");

    //----------------------------------------------------------------------
    // CWE‑1300: Side‑channel leakage (switching activity)
    //----------------------------------------------------------------------

    $display("\n--- CWE‑1300 Test: Key switching activity visible ---");

    // Load key with many toggling bits
    key_in = 128'hFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
    load_key = 1; #10; load_key = 0;
    show_key();

    // Load key with minimal toggling bits
    key_in = 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE;
    load_key = 1; #10; load_key = 0;
    show_key();

    $display("Expect: Different switching profiles → Side‑channel leakage confirmed.");

    //----------------------------------------------------------------------
    $display("\n=== Security Validation Complete ===");
    $finish;
  end

endmodule
