module test_secure (
  input            clk,
  input            rst_n,
  input            cmd_enter,      // start comparison
  input            priv_ok,       // privilege gate (must be 1 for access)
  input  [7:0]     key_in,        // untrusted key candidate
  input  [7:0]     correct_pin,   // trusted key from secure domain
  output reg       access_granted
);
  reg  [3:0] bit_idx;
  reg        match_bit;
  reg        busy;                // comparison in progress

  // Default-deny, privilege-gated, constant-time compare, full scrubbing
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      bit_idx        <= 0;
      match_bit      <= 0;
      busy           <= 0;
      access_granted <= 0;
    end
    else begin
      // Start new attempt: scrub all state, default-deny
      if (cmd_enter && !busy) begin
        bit_idx        <= 0;
        match_bit      <= 1;      // assume match, clear on mismatch
        busy           <= 1;
        access_granted <= 0;      // scrub old authorization
      end
      // Comparison phase: constant-time, always 8 cycles
      else if (busy && bit_idx < 4'd8) begin
        match_bit <= match_bit & (key_in[bit_idx] == correct_pin[bit_idx]);
        bit_idx   <= bit_idx + 1;
      end
      // Decision phase: only after full 8-bit compare
      else if (busy && bit_idx == 4'd8) begin
        // privilege gate + default-deny
        if (priv_ok && match_bit)
          access_granted <= 1;
        else
          access_granted <= 0;

        // scrub internal state immediately after use
        bit_idx   <= 0;
        match_bit <= 0;
        busy      <= 0;
      end
    end
  end
endmodule
