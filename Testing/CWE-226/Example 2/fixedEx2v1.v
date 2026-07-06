module secure_key_reg (
  input        clk,
  input        rst_n,

  // Privilege / lifecycle controls (hardware-derived)
  input        priv_ok,     // 1 = privileged, trusted context
  input        lock_set,    // 1 = request to lock key register (write-once)

  // Key control interface
  input        load_key,    // request to load a new key
  input        clear_key,   // request to scrub key

  input  [127:0] key_in,    // key input from secure source

  // Status-only outputs (no raw key exposure)
  output        key_valid,  // 1 = key_reg holds a non-zero key
  output        key_locked  // 1 = key_reg can no longer be modified
);

  reg [127:0] key_reg;
  reg         locked;

  assign key_valid  = (key_reg != 128'h0);
  assign key_locked = locked;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // CWE-226: scrub on reset, default-deny on access
      key_reg <= 128'h0;
      locked  <= 1'b0;
    end else begin
      // CWE-1262: lock is write-once, privileged-only
      if (priv_ok && lock_set && !locked)
        locked <= 1'b1;

      // CWE-226: explicit scrub before reuse, privileged-only
      if (priv_ok && clear_key)
        key_reg <= 128'h0;
      else if (priv_ok && load_key && !locked) begin
        // CWE-1256/1262: privileged-only write, blocked when locked
        key_reg <= key_in;
      end
      // No path ever exposes key_reg directly
    end
  end

endmodule
