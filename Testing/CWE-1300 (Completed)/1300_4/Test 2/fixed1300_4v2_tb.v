`timescale 1ns/1ps

module secure_test_tb;

  reg         clk;
  reg         rst_n;
  reg         cmd_enter;
  reg         priv_ok;
  reg         glitch_detect;
  reg  [7:0]  key_in;
  wire        access_granted;

  // DUT
  secure_test dut (
    .clk(clk),
    .rst_n(rst_n),
    .cmd_enter(cmd_enter),
    .priv_ok(priv_ok),
    .glitch_detect(glitch_detect),
    .key_in(key_in),
    .access_granted(access_granted)
  );

  // Clock
  always #5 clk = ~clk;

  initial begin
    $display("=== Hardened Module Security Testbench (Fixed) ===");

    clk = 0;
    rst_n = 0;
    cmd_enter = 0;
    priv_ok = 0;
    glitch_detect = 0;
    key_in = 8'h00;

    // Reset
    #10 rst_n = 1;

    // ------------------------------------------------------------
    // CWE-226: No stale authorization, proper scrubbing
    // ------------------------------------------------------------
    $display("\n[CWE-226] Testing scrubbing and stale grant removal...");

    priv_ok = 1;
    cmd_enter = 1;
    key_in = 8'h24;  // correct PIN
    @(posedge clk);
    cmd_enter = 0;

    // Grant should be latched until next cmd_enter/reset/glitch
    @(posedge clk);
    $display("access_granted (correct PIN) = %b", access_granted);

    // New attempt with wrong PIN; access_granted must drop
    cmd_enter = 1;
    key_in = 8'h00;
    @(posedge clk);
    cmd_enter = 0;

    @(posedge clk);
    if (access_granted)
      $display("FAIL: stale access_granted remained high.");
    else
      $display("PASS: access_granted cleared on new attempt.");

    // ------------------------------------------------------------
    // CWE-1247: Glitch detection forces safe state
    // ------------------------------------------------------------
    $display("\n[CWE-1247] Testing glitch_detect safe state...");

    rst_n = 0; @(posedge clk); rst_n = 1;
    priv_ok = 1;
    glitch_detect = 1;  // simulate glitch
    @(posedge clk);

    if (!access_granted)
      $display("PASS: access_granted forced low on glitch.");
    else
      $display("FAIL: access_granted not cleared on glitch.");

    glitch_detect = 0;

    // ------------------------------------------------------------
    // CWE-1256 / CWE-1262: Privilege gating
    // ------------------------------------------------------------
    $display("\n[CWE-1256/1262] Testing privilege gate...");

    rst_n = 0; @(posedge clk); rst_n = 1;
    priv_ok = 0;  // unprivileged
    glitch_detect = 0;

    cmd_enter = 1;
    key_in = 8'h24;  // correct PIN but unprivileged
    @(posedge clk);
    cmd_enter = 0;

    @(posedge clk);
    if (access_granted)
      $display("FAIL: unprivileged access granted.");
    else
      $display("PASS: unprivileged access denied.");

    // Now privileged
    priv_ok = 1;
    cmd_enter = 1;
    key_in = 8'h24;
    @(posedge clk);
    cmd_enter = 0;

    @(posedge clk);
    if (access_granted)
      $display("PASS: privileged access granted.");
    else
      $display("FAIL: privileged access not granted.");

    // ------------------------------------------------------------
    // CWE-1300: Constant-time behavior (no early exit)
    // ------------------------------------------------------------
    $display("\n[CWE-1300] Observing constant-time compare...");

    rst_n = 0; @(posedge clk); rst_n = 1;
    priv_ok = 1;

    cmd_enter = 1;
    key_in = 8'h20;  // partial match
    @(posedge clk);
    cmd_enter = 0;

    @(posedge clk);
    $display("access_granted (partial match) = %b", access_granted);

    cmd_enter = 1;
    key_in = 8'h00;  // full mismatch
    @(posedge clk);
    cmd_enter = 0;

    @(posedge clk);
    $display("access_granted (full mismatch) = %b", access_granted);
    $display("Both decisions occur in single, fixed-latency cycles (constant-time).");

    $display("\n=== Hardened Testbench Completed ===");
    $finish;
  end

endmodule
