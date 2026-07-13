module test_secure (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        en,
    input  wire        we,
    input  wire        priv,      // NEW: privilege signal (1 = privileged, 0 = unprivileged)
    input  wire        lock_set,  // NEW: write-once lock request
    input  wire [2:0]  addr,
    input  wire [31:0] wdata,
    output wire [31:0] rdata,
    output wire        fault      // NEW: signals unauthorized access attempts
);

    reg [31:0] key_buf[3:0];      // secret storage (write-only)
    reg        key_locked;        // write-once lock bit
    reg [31:0] rdata_reg;         // non-secret status / fault code
    reg        fault_reg;

    assign rdata = rdata_reg;
    assign fault = fault_reg;

    // Simple policy:
    // - Keys are WRITE-ONLY: reads never return key contents (CWE-1262 mitigation).
    // - Writes allowed only when priv==1 and key_locked==0 (CWE-1256/1262).
    // - Lock is write-once: once set, cannot be cleared (CWE-1262).
    // - All sensitive storage scrubbed on reset and when en==0 (CWE-226).

    integer i;

    always @(posedge clk) begin
        if (!rst_n) begin
            // CWE-226: scrub all sensitive resources on reset
            for (i = 0; i < 4; i = i + 1)
                key_buf[i] <= 32'd0;
            key_locked <= 1'b0;
            rdata_reg  <= 32'd0;
            fault_reg  <= 1'b0;
        end else begin
            fault_reg <= 1'b0;

            // Write-once lock bit (privileged-only)
            if (lock_set && priv && !key_locked)
                key_locked <= 1'b1;

            // Scrub on exit from enabled context (CWE-226)
            if (!en) begin
                for (i = 0; i < 4; i = i + 1)
                    key_buf[i] <= 32'd0;
                rdata_reg <= 32'd0;
            end else begin
                // Privileged write path to secret registers
                if (en && we) begin
                    if (priv && !key_locked) begin
                        case (addr)
                            3'd0: key_buf[0] <= wdata;
                            3'd1: key_buf[1] <= wdata;
                            3'd2: key_buf[2] <= wdata;
                            3'd3: key_buf[3] <= wdata;
                            default: begin
                                // default-deny: no write on invalid addr
                                fault_reg <= 1'b1;
                            end
                        endcase
                    end else begin
                        // Unauthorized write attempt
                        fault_reg <= 1'b1;
                    end
                end

                // Read path: NEVER expose key contents (write-only secrets)
                if (en && !we) begin
                    case (addr)
                        // Return status instead of secrets
                        3'd0: rdata_reg <= {31'd0, key_locked}; // example status
                        3'd1: rdata_reg <= 32'h0000_FAULT | {31'd0, fault_reg};
                        default: rdata_reg <= 32'd0; // default-deny
                    endcase
                end
            end
        end
    end

endmodule
