// Testbench for Ex1 targeting CWE-226, CWE-1256, CWE-1262
// NOTE: This TB is written to *expose* the vulnerabilities and
// to encode the secure design rules as assertions. In the current
// RTL, these assertions will FAIL, demonstrating the issues.

`timescale 1ns/1ps
module Ex1_tb;
  // DUT interface
  reg         clk;
  reg         reset;
  reg         load_secret;
  reg         reuse_buffer;
  reg  [127:0] secret_in;
  reg  [127:0] public_in;
  wire [127:0] data_out;

  // Simple "privilege mode" model for CWE-1256 / CWE-1262 checks
  // 1'b1 = privileged, 1'b0 = unprivileged
  reg         priv_mode;

  // Instantiate DUT
  Ex1 dut (
    .clk         (clk),
    .reset       (reset),
    .load_secret (load_secret),
    .reuse_buffer(reuse_buffer),
    .secret_in   (secret_in),
    .public_in   (public_in),
    .data_out    (data_out)
  );

  // Clock generation
  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  // Stimulus
  initial begin
    // Initialize
    reset        = 1'b1;
    load_secret  = 1'b0;
    reuse_buffer = 1'b0;
    secret_in    = 128'h0;
    public_in    = 128'h0;
    priv_mode    = 1'b1; // start in privileged mode

    // Apply reset
    #12;
    reset = 1'b0;

    // -------------------------------
    // CWE-226: Resource reuse / scrub
    // -------------------------------
    // 1) Load a known secret pattern
    secret_in   = 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF;
    load_secret = 1'b1;
    @(posedge clk);
    load_secret = 1'b0;

    // Check that secret is visible (baseline)
    @(posedge clk);
    $display("CWE-226 baseline: data_out after secret load = %h", data_out);

    // 2) Reuse buffer with public data (new owner)
    public_in    = 128'h0123_4567_89AB_CDEF_F0F1_F2F3_F4F5_F6F7;
    reuse_buffer = 1'b1;
    @(posedge clk);
    reuse_buffer = 1'b0;

    // Rule: After reuse, new owner must not see prior contents.
    // In secure design, data_out should NOT show old secret.
    @(posedge clk);
    if (data_out == 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF) begin
      $error("CWE-226 VIOLATION: secret value still observable after buffer reuse!");
    end

    // Rule: Confirm data is zeroed or overwritten before new access.
    // Here we expect buffer to have been scrubbed before reuse.
    // Since we cannot see buffer directly, we infer via data_out.
    if (data_out != public_in) begin
      $error("CWE-226 VIOLATION: buffer/data_out not properly overwritten with new public data!");
    end

    // 3) Test that important data is removed before transitions:
    // Force another reuse and check that no old secret leaks.
    public_in    = 128'hA5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5;
    reuse_buffer = 1'b1;
    @(posedge clk);
    reuse_buffer = 1'b0;
    @(posedge clk);
    if (data_out == 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF) begin
      $error("CWE-226 VIOLATION: secret persists across multiple reuse operations!");
    end

    // ---------------------------------------------
    // CWE-1256 / CWE-1262: Privilege & access control
    // ---------------------------------------------

    // Switch to UNPRIVILEGED mode
    priv_mode = 1'b0;
    $display("Entering unprivileged mode...");

    // From unprivileged mode, attempt to manipulate secret-handling features
    // Rule (CWE-1256): software-accessible interfaces should NOT control hardware-only features.
    // Rule (CWE-1262): unprivileged mode must not read/write privileged registers.

    // Attempt to load secret from unprivileged mode
    secret_in   = 128'hCAFEBABE_CAFEBABE_CAFEBABE_CAFEBABE;
    load_secret = 1'b1;
    @(posedge clk);
    load_secret = 1'b0;
    @(posedge clk);

    // In a secure design, unprivileged writes should have NO effect on secret-bearing registers.
    // We model that expectation here; current RTL will violate it.
    if (data_out == 128'hCAFEBABE_CAFEBABE_CAFEBABE_CAFEBABE) begin
      $error("CWE-1256 / CWE-1262 VIOLATION: unprivileged interface can load and expose secret data!");
    end

    // Attempt to reuse buffer with public data from unprivileged mode
    public_in    = 128'h1111_2222_3333_4444_5555_6666_7777_8888;
    reuse_buffer = 1'b1;
    @(posedge clk);
    reuse_buffer = 1'b0;
    @(posedge clk);

    // Expectation: unprivileged mode should not be able to change privileged buffer/output.
    // Current design allows it, so we flag that.
    if (data_out == public_in) begin
      $error("CWE-1256 / CWE-1262 VIOLATION: unprivileged mode can modify shared buffer/output!");
    end

    // Try "self-elevation" via interface (CWE-1262 rule: privilege cannot be self-elevated)
    // Here we conceptually treat load_secret/reuse_buffer as privileged-only controls.
    // From unprivileged mode, toggling them should not grant access to secret behavior.
    secret_in   = 128'h9999_9999_9999_9999_9999_9999_9999_9999;
    load_secret = 1'b1;
    @(posedge clk);
    load_secret = 1'b0;
    @(posedge clk);

    if (data_out == secret_in) begin
      $error("CWE-1262 VIOLATION: unprivileged control path effectively elevates privilege to access secret register!");
    end

    // Final check: in a secure design, unprivileged reads of secret-bearing registers
    // should return masked/zero values.
    if (data_out !== 128'h0 && priv_mode == 1'b0) begin
      $error("CWE-1262 VIOLATION: unprivileged read returns non-zero (potentially secret) data!");
    end

    $display("Testbench completed (expect errors for current insecure RTL).");
    #20;
    $finish;
  end

endmodule
