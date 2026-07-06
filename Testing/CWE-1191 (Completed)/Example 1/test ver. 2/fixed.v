module jtag_debug_ctrl_secure (
    input  wire        clk,
    input  wire        rst_n,

    // Lifecycle / production fuse (1 = production, 0 = development)
    input  wire        lc_prod,

    // Current CPU/system privilege level (0=user, 3=root)
    input  wire [1:0]  current_privilege,

    // Debug authentication status (1 = authenticated debug session)
    input  wire        dbg_auth_ok,

    // JTAG debug interface (raw pins)
    input  wire        dbg_en,       // external debug enable request
    input  wire        dbg_wr,       // 1=write, 0=read
    input  wire [3:0]  dbg_addr,     // register address
    input  wire [31:0] dbg_wdata,    // write data
    output reg  [31:0] dbg_rdata,    // read data

    // System status outputs
    output wire [1:0]  privilege_level,
    output wire [31:0] secret_key
);

    // Internal security-sensitive registers
    reg [31:0] secret_key_reg;     // secret key (never directly exposed via debug)
    reg [1:0]  privilege_reg;      // privilege level (0=user, 3=root)
    reg [31:0] status_reg;         // system status (non-sensitive)
    reg        config_locked;      // lock after boot configuration
    reg        debug_locked;       // permanent debug lock bit

    assign secret_key      = secret_key_reg;
    assign privilege_level = privilege_reg;

    // Effective debug enable:
    // - Disabled in production lifecycle (lc_prod == 1)
    // - Requires authentication (dbg_auth_ok == 1)
    // - Requires high privilege (current_privilege == 2'b11)
    // - Cannot be used once debug_locked is set
    wire dbg_en_effective = dbg_en &&
                            !lc_prod &&
                            dbg_auth_ok &&
                            (current_privilege == 2'b11) &&
                            !debug_locked;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Reset values
            secret_key_reg <= 32'hDEADBEEF;  // initial key
            privilege_reg  <= 2'b00;         // default: user privilege
            status_reg     <= 32'h0;
            dbg_rdata      <= 32'h0;
            config_locked  <= 1'b0;
            debug_locked   <= 1'b0;
        end else begin
            // Example: lock configuration after first few cycles or explicit event
            // Here we simply lock after reset deassertion (could be driven by firmware)
            if (!config_locked) begin
                // After initial boot, lock configuration
                config_locked <= 1'b1;
            end

            // Debug lock can be set by secure firmware (not via debug)
            // (In a real design, debug_locked would be written only from a secure bus)
            // For this example, we assume it is set elsewhere and never cleared.

            // Debug access (only if dbg_en_effective is true)
            if (dbg_en_effective) begin
                if (dbg_wr) begin
                    // WRITE path
                    case (dbg_addr)
                        // 0x0: secret_key_reg is NOT writable via debug once config_locked
                        4'h0: begin
                            if (!config_locked) begin
                                // Allow key provisioning only before lock
                                secret_key_reg <= dbg_wdata;
                            end
                            // After config_locked, writes are ignored
                        end

                        // 0x1: privilege_reg is privilege-gated and locked after config
                        4'h1: begin
                            if (!config_locked) begin
                                // Allow initial privilege configuration only before lock
                                privilege_reg <= dbg_wdata[1:0];
                            end
                            // After config_locked, writes are ignored
                        end

                        // 0x2: status_reg is non-sensitive; allow debug writes
                        4'h2: begin
                            status_reg <= dbg_wdata;
                        end

                        // 0x3: debug lock bit (write-once, only from authenticated debug)
                        4'h3: begin
                            // Once set, debug_locked cannot be cleared
                            if (dbg_wdata[0])
                                debug_locked <= 1'b1;
                        end

                        default: ;
                    endcase
                end else begin
                    // READ path
                    case (dbg_addr)
                        // 0x0: secret_key_reg is masked; never expose full key
                        4'h0: begin
                            // Return zero or a masked value instead of the real key
                            dbg_rdata <= 32'h0;
                        end

                        // 0x1: privilege_reg is visible (non-secret), but only to authenticated debug
                        4'h1: begin
                            dbg_rdata <= {30'h0, privilege_reg};
                        end

                        // 0x2: status_reg is non-sensitive; fully readable
                        4'h2: begin
                            dbg_rdata <= status_reg;
                        end

                        // 0x3: debug lock status (for secure diagnostics)
                        4'h3: begin
                            dbg_rdata <= {31'h0, debug_locked};
                        end

                        default: begin
                            dbg_rdata <= 32'hDEAD_DEAD;
                        end
                    endcase
                end
            end else begin
                // When debug is not effectively enabled, do not change dbg_rdata
                // Optionally, we can force dbg_rdata to a safe value
                // dbg_rdata <= 32'h0;
            end
        end
    end

endmodule
