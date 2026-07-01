module test(
    input wire clk,
    input wire lock,      
    input wire debug,     
    input wire write_en,    
    input wire [7:0] data_in,
    output reg [7:0] lock_bits
);

always @(posedge clk) begin
    if (write_en && (lock || debug)) begin
        lock_bits <= data_in;
    end
end

endmodule