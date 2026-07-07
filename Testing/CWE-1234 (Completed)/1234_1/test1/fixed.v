module test (
    input  [15:0] Data_in,
    input         Clk,
    input         rstn,
    input         write,
    input         Lock,
    input         scan_mode,       // kept for compatibility, no longer overrides lock
    input         debug_unlocked,  // kept for compatibility, no longer overrides lock
    input         glitch_detect,   // new: glitch detector input
    output reg [15:0] Data_out
);

  reg lock_status;

  // Lock bit: set-only, never cleared by debug or Lock=0
  always @(posedge Clk or negedge rstn) begin
    if (!rstn) begin
      // Power-on: default unlocked; system-level policy can choose 0 or 1
      lock_status <= 1'b0;
    end else if (glitch_detect) begin
      // On glitch, force safe state: locked
      lock_status <= 1'b1;
    end else if (Lock) begin
      // One-way fuse behavior: once set, stays set
      lock_status <= 1'b1;
    end
    // no else: lock_status holds its value
  end

  // Data_out: scrubbed on reset, lock transition, and glitch; writes only when unlocked
  always @(posedge Clk or negedge rstn) begin
    if (!rstn) begin
      Data_out <= 16'h0000;
    end else if (glitch_detect) begin
      // CWE-1247: force safe value on glitch
      Data_out <= 16'h0000;
    end else if (Lock && !lock_status) begin
      // CWE-226: scrub on transition into locked state
      Data_out <= 16'h0000;
    end else if (write && !lock_status) begin
      // Normal write path: lock must be clear; debug/test cannot bypass
      Data_out <= Data_in;
    end else begin
      // Hold value otherwise
      Data_out <= Data_out;
    end
  end

endmodule
