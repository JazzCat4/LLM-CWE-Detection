module test (
    input wire clk,
    input wire rst,
    input wire write_en,
    input wire debug_mode,
    input wire [7:0] data_in,
    output reg [7:0] protected_reg
);

reg lock_bit;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        protected_reg <= 8'h00;
        lock_bit <= 1'b0;
    end
    else begin
        if ((write_en && !lock_bit) || debug_mode) begin
            protected_reg <= data_in;
        end
        
        if (data_in == 8'hFF && (write_en || debug_mode)) begin
            lock_bit <= 1'b1;
        end
    end
end

endmodule