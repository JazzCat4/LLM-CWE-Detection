module Ex1 (
    input wire clk,
    input wire reset,
    input wire load_secret,
    input wire reuse_buffer,
    input wire [127:0] secret_in,
    input wire [127:0] public_in,
    output reg [127:0] data_out
);

// Shared buffer resource
reg [127:0] buffer;

always @(posedge clk or posedge reset) begin
    if (reset) begin
        buffer <= 128'b0;
        data_out <= 128'b0;
    end else begin
        if (load_secret) begin
            buffer <= secret_in;
            data_out <= buffer; 
        end
        
        if (reuse_buffer) begin
       
            buffer <= public_in; 
            data_out <= buffer; 
        end
    end
end

endmodule