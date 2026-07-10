`timescale 1ns/1ps

module test_tb;

  reg         clk;
  reg         rst_n;
  reg         cmd_enter;
  reg  [7:0]  key_in;
  wire        access_granted;

  // DUT
  test dut (
    .clk(clk),
    .rst_n(rst_n),
    .cmd_enter(cmd_enter),
    .key_in(key_in),
    .access_granted(access_granted)
  );

  // Clock
  always #5 clk = ~clk;

  // Glitch injection task (CWE‑1247)
  task glitch_clock;
    begin
      #1 clk = ~clk;   // force an unexpected edge
      #1 clk = ~clk;   // restore
    end
  endtask

  initial begin
    $display("=== Security Vulnerability Validation Testbench ===");

    clk = 0;
    rst_n = 0;
    cmd_enter = 0;
    key_in = 8'h00;

    // ============================================================
    // CWE‑226: Sensitive Information Not Removed Before Reuse
    // ============================================================
    $display("\n[CWE‑226] Testing stale secret and stale authorization reuse...");

    #10 rst_n = 1;

    // First attempt: correct PIN
    cmd_enter = 1; #10 cmd_enter = 0;
    key_in = 8'h24;  // correct PIN
    repeat(10) @(posedge clk);

    if (access_granted)
      $display("PASS: Access granted for correct PIN.");
    else
      $display("FAIL: Correct PIN did not grant access.");

    // Start new attempt WITHOUT clearing access_granted
    cmd_enter = 1; #10 cmd_enter = 0;
    key_in = 8'h00; // wrong PIN
    repeat(2) @(posedge clk);

    if (access_granted)
      $display("VULNERABILITY: access_granted remained HIGH across new attempt (stale authorization).");
    else
      $display("OK: access_granted cleared.");

    // ============================================================
    // CWE‑1247: Glitch Susceptibility
    // ============================================================
    $display("\n[CWE‑1247] Testing glitch‑induced bypass...");

    rst_n = 0; #10 rst_n = 1;

    cmd_enter = 1; #10 cmd_enter = 0;
    key_in = 8'h00; // wrong PIN

    repeat(3) @(posedge clk);

    // Inject glitch during comparison
    glitch_clock();

    repeat(10) @(posedge clk);

    if (access_granted)
      $display("VULNERABILITY: Glitch caused incorrect access_granted HIGH.");
    else
      $display("OK: Glitch did not bypass authentication.");

    // ============================================================
    // CWE‑1256 / CWE‑1262: No Privilege Gating, Untrusted Access
    // ============================================================
    $display("\n[CWE‑1256 / CWE‑1262] Testing unrestricted unprivileged access...");

    rst_n = 0; #10 rst_n = 1;

    // Unprivileged software drives cmd_enter and key_in
    cmd_enter = 1; #10 cmd_enter = 0;
    key_in = 8'h24; // correct PIN

    repeat(10) @(posedge clk);

    if (access_granted)
      $display("VULNERABILITY: Unprivileged input successfully triggered privileged access.");
    else
      $display("OK: Access not granted.");

    // ============================================================
    // CWE‑1300: Side‑Channel Leakage (Timing / Bit‑wise Behavior)
    // ============================================================
    $display("\n[CWE‑1300] Testing timing leakage via bit‑serial comparison...");

    rst_n = 0; #10 rst_n = 1;

    cmd_enter = 1; #10 cmd_enter = 0;

    // Try inputs that match only the first bit
    key_in = 8'h20; // matches bit 5 only
    repeat(3) @(posedge clk);

    $display("Observation: match_bit = %b, bit_idx = %d", dut.match_bit, dut.bit_idx);

    // Try inputs that mismatch early
    rst_n = 0; #10 rst_n = 1;
    cmd_enter = 1; #10 cmd_enter = 0;
    key_in = 8'h00;
    repeat(3) @(posedge clk);

    $display("Observation: match_bit = %b, bit_idx = %d", dut.match_bit, dut.bit_idx);

    $display("If match_bit diverges at different cycles, timing/power leakage is present.");

    $display("\n=== Testbench Completed ===");
    $finish;
  end

endmodule
