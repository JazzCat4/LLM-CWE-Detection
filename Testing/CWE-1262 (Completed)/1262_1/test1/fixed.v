module test_secure(
    input         clk,
    input         reset,          // active-high synchronous reset
    input         glitch_detect,  // from glitch detector
    input  [31:0] write_data,
    input         req,
    input  [1:0]  priv_lvl,
    output [31:0] read_data,
    output        fault           // indicates error/glitch state
);

    // State and assets
    reg [31:0] REG_STAT  = 32'h0;
    reg [31:0] REG_CONF  = 32'h0;
    reg [31:0] REG_SKEY  = 32'h0;   // secret key, never directly readable
    reg        LOCK_CONF = 1'b0;    // write-once lock for REG_CONF
    reg        LOCK_SKEY = 1'b0;    // write-once lock for REG_SKEY
    reg        error_state = 1'b0;

    // Default-deny read policy: no secret key ever exposed
    assign read_data = (req && !error_state && priv_lvl >= 2'd2)
                       ? REG_CONF
                       : 32'd0;

    assign fault = error_state;

    always @(posedge clk or posedge reset or posedge glitch_detect) begin
        if (reset || glitch_detect) begin
            // CWE-226, CWE-1247: scrub all sensitive state, enter safe error state on glitch
            REG_STAT    <= 32'h0;
            REG_CONF    <= 32'h0;
            REG_SKEY    <= 32'h0;
            LOCK_CONF   <= 1'b0;
            LOCK_SKEY   <= 1'b0;
            error_state <= glitch_detect; // set error on glitch
        end else begin
            // Normal operation, default-deny unless privilege allows
            if (req && !error_state) begin
                // CWE-1262/1256: privilege-gated config register
                if (priv_lvl >= 2'd2 && !LOCK_CONF) begin
                    REG_CONF  <= write_data;
                    LOCK_CONF <= 1'b1; // write-once lock
                end

                // CWE-1262/1256: stronger privilege for secret key, write-only, lock-once
                if (priv_lvl >= 2'd3 && !LOCK_SKEY) begin
                    REG_SKEY  <= write_data;
                    LOCK_SKEY <= 1'b1; // cannot be cleared
                end
            end
        end
    end

endmodule
