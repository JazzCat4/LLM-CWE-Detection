// https://cwe.mitre.org/data/definitions/226.html
module cwe226 (
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
        // Load sensitive information into the buffer
        if (load_secret) begin
            buffer <= secret_in;
            data_out <= buffer; // Secret exposed (intended)
        end
        
        // Reuse same buffer for non-sensitive data
        if (reuse_buffer) begin
            // VULNERABILITY
            // If reuse_buffer is asserted before buffer is overwritten, data_out can still expose the previous secret value
            buffer <= public_in; // Overwrite, but no explicit clearing
            data_out <= buffer; // may transiently expose old secret
        end
    end
end

endmodule