module test_secure (
    output reg [7:0] data_out,
    input      [2:0] usr_id,
    input      [7:0] data_in,
    input            clk,
    input            rst_n,
    input            glitch_err   // from system-level glitch detector
);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Defensive default on reset
            data_out <= 8'h0;
        end
        else if (glitch_err) begin
            // Defensive default on glitch/error
            data_out <= 8'h0;
        end
        else begin
            // Direct, single-source privilege check
            if (usr_id == 3'h4) begin
                data_out <= data_in;   // privileged write
            end
            else begin
                data_out <= data_out;  // hold value
            end
        end
    end

endmodule
