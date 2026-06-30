module Ex6(
    input wire clk,
    input wire reset,

    // Software-configured region
    input wire cfg_we, // write enable for region config
    input wire [31:0] cfg_start, // region start address
    input wire [31:0] cfg_end, // region end address

    // Memory access request
    input wire [31:0] access_addr,
    output reg access_allowed
);
// Protected memory region (e.g., secure firmware)
localparam [31:0] PROT_START = 32'h1000_0000;
localparam [31:0] PROT_END = 32'h1000_FFFF;

// Software-defined region
reg [31:0] region_start;
reg [31:0] region_end;

always@(posedge clk or posedge reset) begin
    if (reset) begin
        region_start <= 32'h0;
        region_end <= 32'h0;
    end else if (cfg_we) begin
        if (!(cfg_start >= PROT_START && cfg_start <= PROT_END)) begin
            region_start <= cfg_start;
            region_end <= cfg_end;
        end
        // if cfg_start is inside protected region, reject
    end

end

// Access control logic
always @(*) begin
    // Allow access if address is inside the configured region
    if (access_addr >= region_start && access_addr <= region_end) access_allowed = 1'b1;
    else access_allowed = 1'b0;
end

endmodule