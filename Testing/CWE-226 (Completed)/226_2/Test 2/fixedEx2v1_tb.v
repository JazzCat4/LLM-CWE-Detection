`timescale 1ns/1ps

module tb_secure_key_reg;

  reg         clk;
  reg         rst_n;
  reg [127:0] key_in;
  reg         load_key;
  reg         priv_ok;
  reg         lock_set;
  reg         glitch_detect;
  wire [127:0] key_reg_read;

  secure_key_reg dut (
    .clk(clk),
    .rst_n(rst_n),
    .key_in(key_in),
    .load_key(load_key),
    .priv_ok(priv_ok),
    .lock_set(lock_set),
    .glitch_detect(glitch_detect),
    .key_reg_read(key_reg_read)
  );

  initial begin
    clk = 0;
    forever #5 clk = ~clk;
  end

  task show_view;
    $display("[%0t] key_reg_read = %h", $time, key_reg_read);
  endtask

  initial begin
    $display("=== Hardened CWE Security Validation Testbench ===");

    rst_n = 0; load_key = 0; key_in = 0;
    priv_ok = 0; lock_set = 0; glitch_detect = 0;
    #12 rst_n = 1; #10;

    // CWE-226: scrub before reuse (external view always zero)
    $display("\n--- CWE-226: Scrub & write-only behavior ---");
    priv_ok = 1;
    key_in = 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222;
    load_key = 1; #10; load_key = 0;
    show_view();

    key_in = 128'h3333_4444_5555_6666_7777_8888_9999_AAAA;
    load_key = 1; #10; load_key = 0;
    show_view();
    $display("Expect: key_reg_read always 0 → no leakage, reuse scrubbed internally.");

    // CWE-1247: glitch forces safe locked state
    $display("\n--- CWE-1247: Glitch forces scrub + lock ---");
    glitch_detect = 1; #10; glitch_detect = 0;
    show_view();
    $display("Expect: key_reg_read = 0, key_locked asserted internally, further loads blocked.");

    // CWE-1256 / 1262: privilege gating and lock
    $display("\n--- CWE-1256/1262: Unprivileged load blocked ---");
    priv_ok = 0;
    key_in = 128'hFACE_FACE_FACE_FACE_FACE_FACE_FACE_FACE;
    load_key = 1; #10; load_key = 0;
    show_view();
    $display("Expect: no change, unprivileged load ignored.");

    // CWE-1262: read access control
    $display("\n--- CWE-1262: Read access always masked ---");
    $display("Reading key_reg_read directly: %h", key_reg_read);
    $display("Expect: always 0 → key not externally readable.");

    // CWE-1300: side-channel surface reduced (no observable key)
    $display("\n--- CWE-1300: External switching independent of key ---");
    priv_ok = 1;
    key_in = 128'hFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
    load_key = 1; #10; load_key = 0; show_view();
    key_in = 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE;
    load_key = 1; #10; load_key = 0; show_view();
    $display("Expect: key_reg_read stays 0 → external timing/power less correlated with key.");

    $display("\n=== Hardened Security Validation Complete ===");
    $finish;
  end

endmodule
