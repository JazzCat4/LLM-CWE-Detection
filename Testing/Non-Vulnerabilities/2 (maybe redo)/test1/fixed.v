module test_secure
  (
   input        CLK,
   input        RST,           // active-low reset (same interface)
   input        enable,
   input [31:0] value,
   input        glitch_detect, // NEW: from voltage/clock glitch detector
   output [7:0] led
  );

  // Multi-bit FSM encoding with explicit ERROR state
  localparam [1:0] S_IDLE  = 2'b00;
  localparam [1:0] S_STEP1 = 2'b01;
  localparam [1:0] S_STEP2 = 2'b10;
  localparam [1:0] S_ERROR = 2'b11;

  reg [31:0] count;
  reg [1:0]  state;

  // Expose upper byte of count
  assign led = count[23:16];

  always @(posedge CLK) begin
    // Synchronous reset with defensive defaults
    if (!RST) begin
      count <= 32'd0;
      state <= S_IDLE;
    end else begin
      // If glitch detected, force ERROR state and freeze count
      if (glitch_detect) begin
        state <= S_ERROR;
        // Optionally, zero count or leave as-is; here we freeze it
        count <= count;
      end else begin
        case (state)
          S_IDLE: begin
            if (enable)
              state <= S_STEP1;
          end

          S_STEP1: begin
            state <= S_STEP2;
          end

          S_STEP2: begin
            count <= count + value;
            state <= S_IDLE;
          end

          S_ERROR: begin
            // Defensive behavior: remain in ERROR until reset
            state <= S_ERROR;
            count <= count;
          end

          default: begin
            // Defensive default: any illegal encoding → ERROR
            state <= S_ERROR;
            count <= count;
          end
        endcase
      end
    end
  end

endmodule
