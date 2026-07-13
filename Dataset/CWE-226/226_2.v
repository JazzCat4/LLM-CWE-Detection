module test (
  input clk,
  input rst_n,
  input [127:0] key_in,
  input load_key,
  output reg [127:0] key_reg 
);

always @(posedge clk or negedge rst_n) begin
  if (!rst_n) begin
    key_reg <= 128'h0;
  end else if (load_key) begin
    key_reg <= key_in;
  end
end

endmodule