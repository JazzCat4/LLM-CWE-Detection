module secure_key_reg (
  input         clk,
  input         rst_n,

  // Data + control
  input  [127:0] key_in,
  input          load_key,      // request to load key
  input          priv_ok,       // privilege check: must be 1 for any key update
  input          lock_set,      // write-once lock request
  input          glitch_detect, // from glitch detector

  // External view: key is NOT directly readable
  output [127:0] key_reg_read   // masked / zeroed view
);

  reg [127:0] key_reg;
  reg         key_locked;

  // Write-only semantics: external read is always zero
  assign key_reg_read = 128'h0;

  // Hardened sequential logic
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // Defensive reset: scrub key and lock
      key_reg    <= 128'h0;
      key_locked <= 1'b0;
    end else if (glitch_detect) begin
      // CWE-1247: force safe state on glitch
      key_reg    <= 128'h0;
      key_locked <= 1'b1;   // lock on glitch → fail closed
    end else begin
      // Write-once lock bit
      if (lock_set && !key_locked)
        key_locked <= 1'b1;

      // CWE-1256 / 1262: privilege + lock gating
      if (load_key && priv_ok && !key_locked) begin
        // CWE-226: scrub before reuse
        key_reg <= 128'h0;          // scrub old key
        key_reg <= key_in;          // then load new key
      end
      // else: no change to key_reg
    end
  end

endmodule
