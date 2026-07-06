module test(
    input         clk,
    input         reset,
    input  [31:0] write_data,
    input         req,
    input  [1:0]  priv_lvl,
    output [31:0] read_data
);

reg [31:0] REG_STAT   = 32'h0;
reg [31:0] REG_CONF   = 32'h0;
reg [31:0] REG_SKEY   = 32'hA55C;

assign read_data = (req) ? REG_SKEY : 32'd0;

always @(posedge clk) begin
    if (!reset) begin
        if (req & priv_lvl > 2'd1)
            REG_CONF <= write_data;
        if (req)
            REG_SKEY <= write_data; 
    end
end

endmodule