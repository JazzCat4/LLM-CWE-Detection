module test(
    input clk,
    input rstn,
    input [11:0] addr,
    input [31:0] wdata, 
    input wr_en, 
    input [1:0] priv_mode, 
    output [31:0] rdata 
);
    reg [31:0] cntrl_reg;
    reg [31:0] key_reg;

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            cntrl_reg <= 32'h0;
            key_reg <= 32'h0;
        end
        else if (wr_en) begin
            case(addr)
                12'h300: cntrl_reg <= wdata;
                12'h8FF: key_reg <= wdata;
                default: ;
            endcase
        end
    end

    assign rdata = (addr == 12'h300) ? cntrl_reg :
                  (addr == 12'h8FF) ? key_reg :
                  32'b0;
endmodule
