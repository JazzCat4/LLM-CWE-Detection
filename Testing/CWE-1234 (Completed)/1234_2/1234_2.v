module test (
    input wire clk,
    input wire rst_n,
    input wire debug_mode,     
    input wire lock_config,     
    input wire write_enable,   
    input wire [7:0] addr,    
    input wire [31:0] data_in, 
    output reg [31:0] data_out 
);

reg [31:0] config_regs [0:255];
reg config_locked;

reg [31:0] mpu_config;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        config_locked <= 1'b0;
        mpu_config <= 32'h0000_0000;
    end else begin
        if (write_enable && addr < 8'hFF) begin
            if (!config_locked || debug_mode) begin
                case (addr)
                    8'h10: mpu_config <= data_in;
                    default: config_regs[addr] <= data_in;
                endcase
            end
        end
        
        if (write_enable && addr == 8'hFF) begin
            if (!config_locked || debug_mode) begin
                config_locked <= data_in[0];
            end
        end
    end
end

always @(*) begin
    if (addr == 8'h10) begin
        data_out = mpu_config;
    end else if (addr == 8'hFF) begin
        data_out = {31'b0, config_locked};
    end else begin
        data_out = config_regs[addr];
    end
end

endmodule
