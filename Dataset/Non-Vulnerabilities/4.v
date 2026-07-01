module test2(
    input        clk,
    input        rst_n,
    input  [1:0] in,
    output reg   detect
);

    reg [2:0] shift_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            shift_reg <= 3'b000;
        else
            shift_reg <= {shift_reg[1:0], in[0]};
    end

    always @(*) begin
        case (shift_reg)
            3'b010: detect = 1'b1;
            3'b101: detect = 1'b1;
            default: detect = 1'b0;
        endcase
    end

endmodule