module test (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        secret_bit,  
    input  wire [7:0]  secret_data, 
    output reg  [7:0]  acc
);

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        acc <= 8'd0;
    end else begin
        if (secret_bit) begin
            acc <= acc + secret_data;  
        end else begin
            acc <= acc;  
        end
    end
end

endmodule
