module test (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        secret_bit,
    input  wire [15:0] data_in,
    output reg  [15:0] acc
);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        acc <= 16'd0;
    end else begin
        acc <= secret_bit ? (acc + data_in)
                          : (acc - data_in);
    end
end

endmodule
