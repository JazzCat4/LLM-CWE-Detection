module test(
    input        clk,
    input        rst,
    input  [7:0] data_in,
    output reg [7:0] data_out
);
    reg [7:0] secret_key;
    reg [3:0] bit_idx;
    reg [7:0] result;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            secret_key <= 8'hA5;
            bit_idx    <= 4'd0;
            result     <= 8'd0;
            data_out   <= 8'd0;
        end else begin
            if (bit_idx < 4'd8) begin
                if (secret_key[bit_idx])
                    result <= result ^ data_in;
                bit_idx <= bit_idx + 1;
            end else begin
                data_out <= result;
                bit_idx  <= 4'd0;
            end
        end
    end
endmodule
