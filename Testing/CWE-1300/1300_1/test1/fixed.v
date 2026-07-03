module test_secure (
    input        clk,
    input        rst,
    input        glitch_detect,     // CWE-1247: external glitch detector
    input  [7:0] data_in,
    input  [7:0] mask_in,           // CWE-1300: blinding/masking input
    output reg [7:0] data_out
);

    // Sensitive registers
    reg [7:0] secret_key;
    reg [7:0] result;
    reg [3:0] bit_idx;

    // CWE-1247: multi-bit FSM encoding (no typedef enum)
    reg [1:0] state;

    // State encodings
    localparam STATE_IDLE  = 2'b01;
    localparam STATE_BUSY  = 2'b10;
    localparam STATE_ERROR = 2'b11;

    // CWE-226: scrubbing task (converted to Verilog block)
    task scrub_all;
        begin
            result   <= 8'd0;
            data_out <= 8'd0;
            bit_idx  <= 4'd0;
        end
    endtask

    // CWE-1300: constant-time masked key-dependent update
    wire [7:0] masked_in   = data_in ^ mask_in;
    wire [7:0] key_mask    = {8{secret_key[bit_idx]}};
    wire [7:0] xor_input   = masked_in & key_mask;
    wire [7:0] next_result = result ^ xor_input;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            secret_key <= 8'hA5;     // still fixed; real design loads securely
            state      <= STATE_IDLE;
            scrub_all();
        end else begin

            // CWE-1247: glitch forces ERROR state + scrub
            if (glitch_detect) begin
                state <= STATE_ERROR;
                scrub_all();
            end else begin

                case (state)

                    // -------------------------
                    // IDLE → start new round
                    // -------------------------
                    STATE_IDLE: begin
                        result   <= 8'd0;      // CWE-226: scrub before reuse
                        data_out <= 8'd0;
                        bit_idx  <= 4'd0;
                        state    <= STATE_BUSY;
                    end

                    // -------------------------
                    // BUSY → constant-time loop
                    // -------------------------
                    STATE_BUSY: begin
                        result <= next_result;  // CWE-1300: mux-like masked update

                        if (bit_idx < 4'd7) begin
                            bit_idx <= bit_idx + 1;
                        end else begin
                            // End of round
                            data_out <= next_result;
                            state    <= STATE_IDLE;

                            // CWE-226: scrub after use
                            result   <= 8'd0;
                            bit_idx  <= 4'd0;
                        end
                    end

                    // -------------------------
                    // ERROR → safe state
                    // -------------------------
                    STATE_ERROR: begin
                        scrub_all();
                        state <= STATE_ERROR;   // remain until reset
                    end

                    // -------------------------
                    // Defensive default
                    // -------------------------
                    default: begin
                        state <= STATE_ERROR;
                        scrub_all();
                    end
                endcase
            end
        end
    end

endmodule
