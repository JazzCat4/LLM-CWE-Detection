module test (
  input            clk,
  input            rst_n,
  input            cmd_enter,
  input  [7:0]     key_in,
  output reg       access_granted
);
  reg  [7:0]   correct_pin = 8'h24; 
  reg  [3:0]   bit_idx;
  reg          match_bit;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      bit_idx         <= 0;
      match_bit       <= 1;
      access_granted  <= 0;
    end
    else if (cmd_enter) begin
      bit_idx   <= 0;
      match_bit <= 1;
    end
    else if (bit_idx < 4'd8) begin
      if (key_in[bit_idx] == correct_pin[bit_idx])
        match_bit <= match_bit;
      else
        match_bit <= 0;
      bit_idx <= bit_idx + 1;
    end
    else begin
      access_granted <= match_bit;
    end
  end
endmodule