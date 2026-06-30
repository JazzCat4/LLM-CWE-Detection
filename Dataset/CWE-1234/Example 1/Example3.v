module Ex3(
    input wire clk,
    input wire reset,

    // Normal system interface
    input wire sys_we,
    input wire [7:0] sys_wdata,

    // debug interface 
    input wire dbg_mode,
    input wire [7:0] dbg_cmd,
    input wire [7:0] dbg_wdata,

    output reg [7:0] secure_reg, // sensitive register
    output reg lock // lock bit protecting secure_reg
);

always @(posedge clk or posedge reset) begin
    if (reset) begin
        secure_reg <= 8'h00;
        lock <= 1'b1; // locked by default
    end else begin
        
        // Normal system write path
        if (sys_we && !lock) begin
            secure_reg <= sys_wdata;
        end

        if (dbg_mode) begin
            case(dbg_cmd)
            8'hAA: begin
                lock <= 1'b0;
            end

            8'hBB: begin
                secure_reg <= dbg_wdata;
            end

            default: begin// NOP
            end

            endcase
        end
    end
end

endmodule