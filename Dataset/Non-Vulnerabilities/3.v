module test(
    output reg [7:0] data_out,
    input [2:0] usr_id,
    input [7:0] data_in,
    input clk,
    input rst_n
);
    reg grant_access;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            data_out <= 8'h0;
        end
        else begin
            grant_access = (usr_id == 3'h4);
            data_out = grant_access ? data_in : data_out;
        end
    end
endmodule