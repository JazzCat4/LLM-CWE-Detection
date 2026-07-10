module secure_test (
  input        clk,
  input        rst_n,
  input        cmd_enter,      // request to authenticate
  input        priv_ok,        // privilege gate: must be 1 for any auth
  input        glitch_detect,  // from analog/glitch detector
  input  [7:0] key_in,
  output reg   access_granted
);

  // Secret stored as a parameter (not a writable register)
  localparam [7:0] SECRET_PIN = 8'h24;

  // Retry / lockout counter (glitch-resistant, saturating)
  reg [3:0] retry_cnt;
  reg       locked;

  wire      pin_match;

  // Constant-time comparison (no early exit, no secret-dependent branching)
  assign pin_match = (key_in == SECRET_PIN);

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      // Defensive reset: scrub all security state
      access_granted <= 1'b0;
      retry_cnt      <= 4'd0;
      locked         <= 1'b0;
    end
    else if (glitch_detect) begin
      // CWE-1247: force safe error state on glitch
      access_granted <= 1'b0;
      locked         <= 1'b1;   // require higher-level recovery
    end
    else if (cmd_enter) begin
      // CWE-226: clear any prior grant on new attempt
      access_granted <= 1'b0;

      // CWE-1256/1262: privilege gate + lockout
      if (priv_ok && !locked) begin
        if (pin_match) begin
          access_granted <= 1'b1;
          retry_cnt      <= 4'd0;   // successful auth clears retries
        end
        else begin
          // Failed attempt: increment saturating counter
          if (retry_cnt != 4'hF)
            retry_cnt <= retry_cnt + 1'b1;

          // Lockout on max retries
          if (retry_cnt == 4'hF)
            locked <= 1'b1;
        end
      end
    end
  end

endmodule
