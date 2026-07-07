module Ex1_secure (
    input  wire        clk,
    input  wire        reset,

    // Normal system interface (assumed privileged when sys_priv == 1)
    input  wire        sys_we,
    input  wire [7:0]  sys_wdata,
    input  wire        sys_priv,   // privilege indicator for system writes

    // Debug interface (must be authenticated + lifecycle-allowed)
    input  wire        dbg_mode_req,   // raw debug request (e.g., JTAG)
    input  wire        dbg_auth_ok,    // debug authentication result
    input  wire        dbg_lifecycle_dev, // 1 in development, 0 in production
    input  wire [7:0]  dbg_cmd,
    input  wire [7:0]  dbg_wdata,

    // Glitch detector (CWE-1247)
    input  wire        glitch_detected,

    output reg  [7:0]  secure_reg, // sensitive register
    output reg         lock        // lock bit protecting secure_reg (one-way)
);

    // ----------------------------------------------------------------
    // Derived, safe debug enable:
    //  - Only in development lifecycle
    //  - Only when authentication passes
    //  - Raw dbg_mode_req is not enough
    // ----------------------------------------------------------------
    wire dbg_mode_safe = dbg_mode_req & dbg_auth_ok & dbg_lifecycle_dev;

    // ----------------------------------------------------------------
    // One-way lock bit:
    //  - Set on reset
    //  - Can be cleared only by privileged system write (no debug override)
    //  - Once set again, cannot be cleared by debug or unprivileged paths
    // ----------------------------------------------------------------
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            // Defensive reset (CWE-226, CWE-1262)
            secure_reg <= 8'h00;
            lock       <= 1'b1;   // locked by default
        end else if (glitch_detected) begin
            // Glitch-safe behavior (CWE-1247): force safe state
            secure_reg <= 8'h00;
            lock       <= 1'b1;
        end else begin
            // -----------------------------
            // Privileged system write path
            // -----------------------------
            if (sys_we && sys_priv) begin
                // Lock enforcement: default-deny (CWE-1262)
                if (!lock) begin
                    secure_reg <= sys_wdata;
                end
                // Optional: allow privileged code to re-lock, but not unlock
                // Example: write a special value to re-lock
                if (sys_wdata == 8'hFF) begin
                    lock <= 1'b1; // re-lock, never unlock via system write
                end
            end

            // -----------------------------
            // Debug path (CWE-1191, CWE-1234)
            // - No direct writes to secure_reg
            // - No ability to clear lock
            // - Only non-sensitive operations allowed
            // -----------------------------
            if (dbg_mode_safe) begin
                case (dbg_cmd)
                    // Example: read-only status, no sensitive data modification
                    8'h10: begin
                        // NOP or status operation; secure_reg and lock unchanged
                    end

                    default: begin
                        // All other debug commands are ignored for safety
                    end
                endcase
            end
        end
    end

endmodule
