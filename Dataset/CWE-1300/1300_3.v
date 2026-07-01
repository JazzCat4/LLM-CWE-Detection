module test (
    input wire clk,
    input wire rst,
    input wire start,
    input wire [31:0] base,
    input wire [31:0] exponent,
    output reg [31:0] result,
    output reg done
);
    reg [31:0] base_reg, exp_reg, res_reg;
    reg [1:0] state;

    localparam IDLE = 2'd0,
               RUN  = 2'd1,
               DONE = 2'd2;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state <= IDLE;
            result <= 0;
            res_reg <= 1;
            done <= 0;
        end else begin
            case (state)
                IDLE: begin
                    if (start) begin
                        base_reg <= base;
                        exp_reg <= exponent;
                        res_reg <= 1;
                        done <= 0;
                        state <= RUN;
                    end
                end
                RUN: begin
                    if (exp_reg != 0) begin
                        if (exp_reg[0] == 1) begin
                            res_reg <= res_reg * base_reg;
                        end
                        base_reg <= base_reg * base_reg;
                        exp_reg <= exp_reg >> 1;
                    end else begin
                        result <= res_reg;
                        state <= DONE;
                    end
                end
                DONE: begin
                    done <= 1;
                    state <= IDLE;
                end
            endcase
        end
    end
endmodule