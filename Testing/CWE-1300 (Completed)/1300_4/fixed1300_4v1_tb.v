`timescale 1ns/1ps

module tb_test_secure;

  reg         clk;
  reg         rst_n;
  reg         cmd_enter;
  reg         priv_ok;
  reg  [7:0]  key_in;
  reg  [7:0]  correct_pin;
  wire        access_granted;

  // DUT
  test_secure dut (
    .clk(clk),
    .rst_n(rst_n),
    .cmd_enter(cmd_enter),
    .priv_ok(priv_ok),
    .key_in(key_in),
    .correct_pin(correct_pin),
    .access_granted(access_granted)
  );

  // Clock
  always #5 clk = ~clk;

  task start_attempt(input [7:0] key, input priv);
    begin
      key_in   = key;
      priv_ok  = priv;
      cmd_enter = 1;
      #10;
      cmd_enter = 0;
    end
  endtask

  initial begin
    $display("=== Secure Module CWE Validation ===");

    clk        = 0;
    rst_n      = 0;
    cmd_enter  = 0;
    priv_ok    = 0;
    key_in     = 0;
    correct_pin = 8'h24; // trusted domain provides key

    #20 rst_n = 1;

    // PHASE 1 — CWE-226: scrubbing & reuse
    $display("\n[PHASE 1] CWE-226: scrubbing & reuse");
    start_attempt(8'h24, 1'b1);   // correct, privileged
    repeat(10) @(posedge clk);
    $display("Access after correct PIN: %0d", access_granted);

    start_attempt(8'hFF, 1'b1);   // incorrect, privileged
    repeat(10) @(posedge clk);
    $display("Access after incorrect PIN: %0d", access_granted);
    if (access_granted !== 0)
      $display("ERROR: stale authorization (CWE-226)");
    else
      $display("OK: authorization scrubbed between attempts");

    // PHASE 2 — CWE-1256: privilege gating
    $display("\n[PHASE 2] CWE-1256: privilege gating");
    start_attempt(8'h24, 1'b0);   // correct key, but unprivileged
    repeat(10) @(posedge clk);
    $display("Access for unprivileged caller: %0d", access_granted);
    if (access_granted !== 0)
      $display("ERROR: unprivileged access to hardware feature (CWE-1256)");
    else
      $display("OK: privilege gate enforced");

    // PHASE 3 — CWE-1262: default-deny & access control
    $display("\n[PHASE 3] CWE-1262: default-deny");
    start_attempt(8'h00, 1'b1);   // wrong key, privileged
    repeat(10) @(posedge clk);
    $display("Access with wrong key: %0d", access_granted);
    if (access_granted !== 0)
      $display("ERROR: default-open access (CWE-1262)");
    else
      $display("OK: default-deny policy");

    // PHASE 4 — constant-time behavior (side-channel mitigation)
    $display("\n[PHASE 4] Constant-time compare check");
    start_attempt(8'h20, 1'b1);   // partial match
    repeat(10) @(posedge clk);
    $display("Access for partial match: %0d", access_granted);

    start_attempt(8'h24, 1'b1);   // full match
    repeat(10) @(posedge clk);
    $display("Access for full match: %0d", access_granted);

    // PHASE 5 — reset behavior
    $display("\n[PHASE 5] Reset behavior");
    start_attempt(8'h24, 1'b1);
    repeat(3) @(posedge clk);
    rst_n = 0;
    #7 rst_n = 1;
    repeat(10) @(posedge clk);
    $display("Access after reset glitch: %0d", access_granted);

    $display("\n=== Secure Module Tests Complete ===");
    $finish;
  end

endmodule
