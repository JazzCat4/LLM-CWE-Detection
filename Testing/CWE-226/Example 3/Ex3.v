module test (
    input wire clk,
    input wire rst,
    input wire write_en,
    input wire read_en,
    input wire [1:0] addr,
    input wire [127:0] secret_key_in,
    output reg [127:0] secret_key_out
);

    reg [127:0] secret_key [0:3];

    always @(posedge clk) begin
        if (rst) begin
            secret_key_out <= 128'b0;
        end else begin
            if (write_en) begin
                secret_key[addr] <= secret_key_in;
            end
            if (read_en) begin
                secret_key_out <= secret_key[addr];
            end
        end
    end

endmodule
