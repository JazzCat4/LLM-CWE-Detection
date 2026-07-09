module test(
    input             clk,
    input             rst_n,
    input      [7:0]  base,
    input      [7:0]  secret_key,
    output reg [15:0] result
);
    reg  [7:0] key_reg;
    reg  [7:0] base_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg  <= secret_key;
            base_reg <= base;
            result   <= 16'd1;
        end
        else begin
            if (key_reg != 0) begin
                if (key_reg[0])
                    result <= result * base_reg;
                key_reg  <= key_reg >> 1;
                base_reg <= base_reg * base_reg;
            end
        end
    end
endmodule
