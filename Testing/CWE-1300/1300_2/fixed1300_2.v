module secure_test (
    input             clk,
    input             rst_n,
    input             priv_en,        // privilege enable (CWE-1256/1262)
    input             glitch_detect,  // glitch detector input (CWE-1247)
    input      [7:0]  base_in,
    input      [7:0]  secret_key_in,
    output reg [15:0] result,
    output reg        error           // error flag on glitch / misuse
);
    reg  [7:0]  key_reg;
    reg  [7:0]  base_reg;
    reg  [3:0]  iter_cnt;             // fixed-iteration counter (constant-time)

    localparam  ITER_MAX = 4'd8;      // 8-bit key → 8 cycles

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub everything on reset
            key_reg   <= 8'd0;
            base_reg  <= 8'd0;
            result    <= 16'd0;
            iter_cnt  <= 4'd0;
            error     <= 1'b0;
        end
        else begin
            // CWE-1247: glitch forces safe error state and scrubs
            if (glitch_detect) begin
                key_reg   <= 8'd0;
                base_reg  <= 8'd0;
                result    <= 16'd0;
                iter_cnt  <= 4'd0;
                error     <= 1'b1;
            end
            else if (priv_en) begin
                // CWE-1256/1262: only privileged context can start operation
                if (iter_cnt == 4'd0) begin
                    // start new constant-time operation
                    key_reg   <= secret_key_in;
                    base_reg  <= base_in;
                    result    <= 16'd1;
                    iter_cnt  <= 4'd1;
                    error     <= 1'b0;
                end
                else if (iter_cnt < ITER_MAX) begin
                    // CWE-1300: constant-time, key-dependent mux (not branch)
                    result   <= result * (key_reg[0] ? base_reg : 16'd1);
                    key_reg  <= key_reg >> 1;
                    base_reg <= base_reg * base_reg;
                    iter_cnt <= iter_cnt + 4'd1;
                end
                else begin
                    // done: scrub sensitive registers (CWE-226)
                    key_reg   <= 8'd0;
                    base_reg  <= 8'd0;
                    iter_cnt  <= 4'd0;
                    // result holds final value; error remains 0
                end
            end
            else begin
                // unprivileged: hold safe state, no operation
                key_reg   <= 8'd0;
                base_reg  <= 8'd0;
                iter_cnt  <= 4'd0;
                // result unchanged; error can indicate misuse if desired
            end
        end
    end
endmodule
