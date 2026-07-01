module test (
    input wire clk,
    input wire rst_n,
    input wire en,
    input wire we,
    input wire [2:0] addr,
    input wire [31:0] wdata,
    output wire [31:0] rdata
);

reg [31:0] key_buf[3:0];
reg [31:0] rdata_reg;

assign rdata = rdata_reg;

always @(posedge clk) begin
    if (!rst_n) begin
        key_buf[0] <= 32'd0;
        key_buf[1] <= 32'd0;
        key_buf[2] <= 32'd0;
        key_buf[3] <= 32'd0;
    end else if (en && we) begin
        case (addr)
            3'd0: key_buf[0] <= wdata;
            3'd1: key_buf[1] <= wdata;
            3'd2: key_buf[2] <= wdata;
            3'd3: key_buf[3] <= wdata;
        endcase
    end else if (en && !we) begin
        case (addr)
            3'd0: rdata_reg <= key_buf[0];
            3'd1: rdata_reg <= key_buf[1];
            3'd2: rdata_reg <= key_buf[2];
            3'd3: rdata_reg <= key_buf[3];
            default: rdata_reg <= 32'd0;
        endcase
    end
end

endmodule