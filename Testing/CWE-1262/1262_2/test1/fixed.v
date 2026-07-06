module test_secure(
    input        clk,
    input        rstn,
    input        glitch_detect,      // CWE-1247: external glitch detector
    input [11:0] addr,
    input [31:0] wdata, 
    input        wr_en, 
    input [1:0]  priv_mode,          // 2'b11 = privileged/secure
    output [31:0] rdata 
);
    // Security-sensitive registers
    reg [31:0] cntrl_reg;
    reg [31:0] key_reg;
    reg        error_state;          // CWE-1247: defensive error state
    reg        key_cleared;          // CWE-226: enforce scrub-before-reuse

    // Privilege check: only 2'b11 is allowed to touch sensitive regs
    wire priv_ok = (priv_mode == 2'b11);

    // Address constants
    localparam ADDR_CNTRL = 12'h300;
    localparam ADDR_KEY   = 12'h8FF;

    // Asynchronous reset + glitch-safe behavior
    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            // CWE-226: zero-fill on reset
            cntrl_reg  <= 32'h0;
            key_reg    <= 32'h0;
            error_state <= 1'b0;
            key_cleared <= 1'b1;     // start in "cleared" state
        end
        else if (glitch_detect) begin
            // CWE-1247: force safe error state on glitch
            cntrl_reg  <= 32'h0;
            key_reg    <= 32'h0;
            error_state <= 1'b1;
            key_cleared <= 1'b1;
        end
        else if (wr_en && priv_ok && !error_state) begin
            // CWE-1262/1256: writes only allowed for privileged, non-error
            case (addr)
                ADDR_CNTRL: begin
                    cntrl_reg <= wdata;

                    // Example: bit 0 of cntrl_reg requests key scrub
                    if (wdata[0]) begin
                        key_reg    <= 32'h0;   // CWE-226: explicit scrub
                        key_cleared <= 1'b1;
                    end
                end

                ADDR_KEY: begin
                    // CWE-226: require scrub-before-reuse
                    if (key_cleared) begin
                        key_reg    <= wdata;
                        key_cleared <= 1'b0;   // key now “in use”
                    end
                    // else: ignore write until scrub requested via cntrl_reg
                end

                default: ;
            endcase
        end
    end

    // Read path with access control and default-deny
    assign rdata =
        (!priv_ok || error_state) ? 32'h0 :          // CWE-1262/1256: deny by default
        (addr == ADDR_CNTRL)      ? cntrl_reg :
        (addr == ADDR_KEY)        ? key_reg   :
                                   32'h0;

endmodule
