`timescale 1ns/1ps

module tb_secure_key_reg;

  reg        clk;
  reg        rst_n;
  reg        priv_ok;
  reg        lock_set;
  reg        load_key;
  reg        clear_key;
  reg [127:0] key_in;
  wire       key_valid;
  wire       key_locked;

  secure_key_reg dut (
    .clk(clk),
    .rst_n(rst_n),
    .priv_ok(priv_ok),
    .lock_set(lock_set),
    .load_key(load_key),
    .clear_key(clear_key),
    .key_in(key_in),
    .key_valid(key_valid),
    .key_locked(key_locked)
  );

  // Clock
  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  initial begin
    $display("=== SECURE KEY REG TESTBENCH START ===");

    // Reset
    rst_n    = 0;
    priv_ok  = 0;
    lock_set = 0;
    load_key = 0;
    clear_key= 0;
    key_in   = 0;
    #20 rst_n = 1; #10;

    // CWE-226: privileged load, then scrub before reuse
    priv_ok  = 1;
    key_in   = 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222;
    load_key = 1; #10 load_key = 0;
    $display("[CWE-226] First key loaded, key_valid=%0d", key_valid);

    clear_key = 1; #10 clear_key = 0;
    $display("[CWE-226] Key scrubbed, key_valid=%0d", key_valid);

    key_in   = 128'h1234_5678_9ABC_DEF0_1357_9BDF_2468_ACED;
    load_key = 1; #10 load_key = 0;
    $display("[CWE-226] Second key loaded after scrub, key_valid=%0d", key_valid);

    // CWE-1256: unprivileged attempt to overwrite key (must fail)
    priv_ok  = 0;
    key_in   = 128'hBAD0_BAD0_BAD0_BAD0_BAD0_BAD0_BAD0_BAD0;
    load_key = 1; #10 load_key = 0;
    $display("[CWE-1256] Unprivileged overwrite blocked, key_valid=%0d", key_valid);

    // CWE-1262: lock key, then block further writes even when privileged
    priv_ok  = 1;
    lock_set = 1; #10 lock_set = 0;
    $display("[CWE-1262] Key locked, key_locked=%0d", key_locked);

    key_in   = 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF;
    load_key = 1; #10 load_key = 0;
    $display("[CWE-1262] Write after lock blocked, key_locked=%0d, key_valid=%0d",
             key_locked, key_valid);

    // Reset scrubbing
    rst_n = 0; #10;
    $display("[CWE-226] After reset, key_valid=%0d, key_locked=%0d",
             key_valid, key_locked);

    $display("=== SECURE KEY REG TESTBENCH END ===");
    $finish;
  end

endmodule
