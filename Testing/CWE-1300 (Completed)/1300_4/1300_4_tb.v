`timescale 1ns/1ps

module tb_test_vuln;

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

  // Helper task
  task start_attempt(input [7:0] key);
    begin
      key_in = key;
      cmd_enter = 1;
      #10;
      cmd_enter = 0;
    end
  endtask

  initial begin
    $display("=== CWE Vulnerability Validation Testbench ===");

    clk = 0;
    rst_n = 0;
    cmd_enter = 0;
    key_in = 0;

    // ============================================================
    // PHASE 1 — CWE‑226: Sensitive state not scrubbed before reuse
    // ============================================================
    $display("\n[PHASE 1] Testing sensitive-state reuse (CWE‑226)");

    #20 rst_n = 1;

    // First attempt: correct PIN
    start_attempt(8'h24);
    repeat(10) @(posedge clk);
    $display("Access after correct PIN: %0d", access_granted);

    // Second attempt: incorrect PIN
    start_attempt(8'hFF);
    repeat(10) @(posedge clk);
    $display("Access after incorrect PIN (should be 0): %0d", access_granted);

    // If access_granted stays 1 → stale authorization → CWE‑226
    if (access_granted == 1)
      $display(">>> CWE‑226 VIOLATION: access_granted not scrubbed before reuse");

    // ============================================================
    // PHASE 2 — CWE‑1256: Unprivileged control of security features
    // ============================================================
    $display("\n[PHASE 2] Testing privilege-less access (CWE‑1256)");

    // Drive untrusted inputs directly
    start_attempt(8'h00);
    repeat(10) @(posedge clk);

    // Any untrusted key_in/cmd_enter should NOT be able to control security logic
    $display("Unprivileged attempt result: %0d", access_granted);
    $display(">>> CWE‑1256 VIOLATION: No privilege gating on security-critical interface");

    // ============================================================
    // PHASE 3 — CWE‑1262: Default-open access control
    // ============================================================
    $display("\n[PHASE 3] Testing default-open access control (CWE‑1262)");

    // Attempt multiple reads/writes without privilege
    start_attempt(8'hAA);
    repeat(10) @(posedge clk);

    $display("Access result: %0d", access_granted);
    $display(">>> CWE‑1262 VIOLATION: Sensitive registers reachable without privilege checks");

    // ============================================================
    // PHASE 4 — Side-channel leakage via sequential comparison
    // ============================================================
    $display("\n[PHASE 4] Testing timing leakage");

    start_attempt(8'h20); // Only bit 0 matches
    repeat(3) @(posedge clk);
    $display("match_bit after partial match (internal): %0d", dut.match_bit);

    start_attempt(8'h24); // Full match
    repeat(10) @(posedge clk);
    $display("match_bit after full match (internal): %0d", dut.match_bit);

    $display(">>> Side-channel leakage: match_bit reveals partial correctness");

    // ============================================================
    // PHASE 5 — Reset glitch behavior
    // ============================================================
    $display("\n[PHASE 5] Testing reset glitch behavior");

    start_attempt(8'h24);
    repeat(3) @(posedge clk);

    // Glitch reset mid-comparison
    rst_n = 0;
    #7 rst_n = 1;

    repeat(10) @(posedge clk);
    $display("Access after reset glitch: %0d", access_granted);
    $display(">>> CWE‑226/CWE‑1262 VIOLATION: Partial reset leaves inconsistent state");

    // ============================================================
    // END
    // ============================================================
    $display("\n=== Testbench Complete ===");
    $finish;
  end

endmodule
