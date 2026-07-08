module test_secure (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire        glitch_detect,   // CWE-1247: external glitch detector
    input  wire [31:0] base,
    input  wire [31:0] exponent,
    output reg  [31:0] result,
    output reg         done
);
    // Internal state
    reg [31:0] base_reg, exp_reg, res_reg;
    reg [5:0]  iter;        // constant-time loop counter (up to 32 bits)
    reg [1:0]  state;

    // FSM states (4-way encoding, defensive default)
    localparam IDLE  = 2'd0,
               RUN   = 2'd1,
               DONE  = 2'd2,
               ERROR = 2'd3;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            // CWE-226: scrub all sensitive registers on reset
            state    <= IDLE;
            result   <= 32'd0;
            res_reg  <= 32'd0;
            base_reg <= 32'd0;
            exp_reg  <= 32'd0;
            iter     <= 6'd0;
            done     <= 1'b0;
        end else if (glitch_detect) begin
            // CWE-1247: force safe ERROR state on glitch
            state    <= ERROR;
            result   <= 32'd0;
            res_reg  <= 32'd0;
            base_reg <= 32'd0;
            exp_reg  <= 32'd0;
            iter     <= 6'd0;
            done     <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    done    <= 1'b0;
                    result  <= 32'd0;
                    res_reg <= 32'd0;
                    base_reg<= 32'd0;
                    exp_reg <= 32'd0;
                    iter    <= 6'd0;
                    if (start) begin
                        // load operands, initialize constant-time loop
                        base_reg <= base;
                        exp_reg  <= exponent;
                        res_reg  <= 32'd1;
                        iter     <= 6'd32;   // constant-time: always 32 iterations
                        state    <= RUN;
                    end
                end

                RUN: begin
                    if (iter != 0) begin
                        // CWE-1300: secret-dependent selection via mux, not branch
                        res_reg  <= (exp_reg[0] ? (res_reg * base_reg) : res_reg);
                        base_reg <= base_reg * base_reg;
                        exp_reg  <= exp_reg >> 1;
                        iter     <= iter - 1'b1;
                    end else begin
                        // commit result and scrub intermediates
                        result   <= res_reg;
                        base_reg <= 32'd0;
                        exp_reg  <= 32'd0;
                        res_reg  <= 32'd0;
                        state    <= DONE;
                    end
                end

                DONE: begin
                    done     <= 1'b1;
                    // CWE-226: ensure all sensitive data cleared before returning to IDLE
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    res_reg  <= 32'd0;
                    iter     <= 6'd0;
                    state    <= IDLE;
                end

                ERROR: begin
                    // Safe sink state; everything scrubbed
                    done     <= 1'b0;
                    result   <= 32'd0;
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    res_reg  <= 32'd0;
                    iter     <= 6'd0;
                    // stay in ERROR until reset or glitch clears externally
                end

                default: begin
                    // CWE-1247: defensive default to ERROR on illegal encoding
                    state    <= ERROR;
                    done     <= 1'b0;
                    result   <= 32'd0;
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    res_reg  <= 32'd0;
                    iter     <= 6'd0;
                end
            endcase
        end
    end
endmodule
