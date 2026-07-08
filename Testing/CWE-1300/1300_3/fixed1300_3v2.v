module test_secure (
    input  wire        clk,
    input  wire        rst,
    input  wire        start,
    input  wire        glitch_detect,   // CWE-1247: glitch detector input
    input  wire [31:0] base,
    input  wire [31:0] exponent,
    output reg  [31:0] result,
    output reg         done
);

    reg [31:0] base_reg, exp_reg, res_reg;
    reg [5:0]  iter;
    reg [1:0]  state;

    localparam IDLE  = 2'd0,
               RUN   = 2'd1,
               DONE  = 2'd2,
               ERROR = 2'd3;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state    <= IDLE;
            result   <= 32'd0;
            res_reg  <= 32'd0;
            base_reg <= 32'd0;
            exp_reg  <= 32'd0;
            iter     <= 6'd0;
            done     <= 1'b0;
        end else if (glitch_detect) begin
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
                    done     <= 1'b0;
                    result   <= 32'd0;
                    res_reg  <= 32'd0;
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    iter     <= 6'd0;

                    if (start) begin
                        base_reg <= base;
                        exp_reg  <= exponent;
                        res_reg  <= 32'd1;
                        iter     <= 6'd32;   // constant-time loop
                        state    <= RUN;
                    end
                end

                RUN: begin
                    if (iter != 0) begin
                        res_reg  <= (exp_reg[0] ? (res_reg * base_reg) : res_reg);
                        base_reg <= base_reg * base_reg;
                        exp_reg  <= exp_reg >> 1;
                        iter     <= iter - 1'b1;
                    end else begin
                        result   <= res_reg;
                        base_reg <= 32'd0;
                        exp_reg  <= 32'd0;
                        res_reg  <= 32'd0;
                        state    <= DONE;
                    end
                end

                DONE: begin
                    done     <= 1'b1;
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    res_reg  <= 32'd0;
                    iter     <= 6'd0;
                    state    <= IDLE;
                end

                ERROR: begin
                    done     <= 1'b0;
                    result   <= 32'd0;
                    base_reg <= 32'd0;
                    exp_reg  <= 32'd0;
                    res_reg  <= 32'd0;
                    iter     <= 6'd0;
                end

                default: begin
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
