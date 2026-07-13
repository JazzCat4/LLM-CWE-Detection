module periph_regs (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        reg_wen,
    input  wire        reg_ren,
    input  wire [2:0]  reg_addr,
    input  wire [31:0] reg_wdata,
    output reg  [31:0] reg_rdata,

    input  wire [1:0]  cpu_privilege_level, // 2'b00 = user, 2'b01 = supervisor, 2'b10+ = secure
    input  wire        user_mode,           // 1 = user, 0 = privileged

    output wire [31:0] crypto_key,
    output wire [31:0] security_config
);

    // -----------------------------
    // Registers
    // -----------------------------
    reg [31:0] security_config_reg;
    reg [31:0] crypto_key_reg;
    reg [31:0] status_reg;
    reg [31:0] version_reg;

    // Lock bit: once set, security_config_reg and crypto_key_reg cannot be modified
    reg        security_lock;

    // Ciphertext-valid flag: when set, key is scrubbed immediately
    wire       ciphertext_valid = status_reg[0];

    assign security_config = security_config_reg;
    assign crypto_key      = crypto_key_reg;

    // -----------------------------
    // Privilege / access control
    // -----------------------------
    // Define privilege levels:
    //  - user_mode == 1 and cpu_privilege_level == 2'b00 => unprivileged
    //  - otherwise => privileged
    wire unprivileged = (user_mode == 1'b1) && (cpu_privilege_level == 2'b00);
    wire privileged   = ~unprivileged;

    // Security-sensitive registers are default-deny:
    //  - Only privileged software can access them
    //  - Writes additionally require lock == 0
    wire priv_can_read_sec_cfg  = privileged;
    wire priv_can_write_sec_cfg = privileged && ~security_lock;

    wire priv_can_read_key      = privileged;
    wire priv_can_write_key     = privileged && ~security_lock;

    // Status and version are less sensitive:
    wire can_read_status  = 1'b1;          // readable by all
    wire can_write_status = privileged;    // writable only by privileged
    wire can_read_version = 1'b1;          // read-only
    wire can_write_version= 1'b0;          // never writable

    // -----------------------------
    // Reset and scrubbing behavior
    // -----------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // On reset, scrub all sensitive registers (CWE-226)
            security_config_reg <= 32'h0000_0000;
            crypto_key_reg      <= 32'h0000_0000;
            status_reg          <= 32'h0000_0000;
            version_reg         <= 32'h0000_0100; // ID/version (non-sensitive)
            security_lock       <= 1'b0;
            reg_rdata           <= 32'h0;
        end else begin
            // -------------------------
            // Scrub key when ciphertext becomes valid (CWE-226)
            // -------------------------
            if (ciphertext_valid) begin
                crypto_key_reg <= 32'h0000_0000;
            end

            // -------------------------
            // Write path with access control (CWE-1262, CWE-1256)
            // -------------------------
            if (reg_wen) begin
                case (reg_addr)
                    // 0: security configuration (privileged, lockable)
                    3'h0: begin
                        if (priv_can_write_sec_cfg) begin
                            security_config_reg <= reg_wdata;
                        end
                        // else: deny write silently or signal fault externally
                    end

                    // 1: crypto key (privileged, lockable, write-only)
                    3'h1: begin
                        if (priv_can_write_key) begin
                            crypto_key_reg <= reg_wdata;
                        end
                        // else: deny write
                    end

                    // 2: status (ciphertext_valid, etc.)
                    3'h2: begin
                        if (can_write_status) begin
                            status_reg <= reg_wdata;
                        end
                    end

                    // 3: version (read-only)
                    3'h3: begin
                        if (can_write_version) begin
                            version_reg <= reg_wdata;
                        end
                    end

                    // 4: security lock bit (write-once, privileged only)
                    3'h4: begin
                        if (privileged) begin
                            // Write-once lock: only allow transition 0 -> 1
                            if (~security_lock && reg_wdata[0]) begin
                                security_lock <= 1'b1;
                            end
                        end
                    end

                    default: ; // no write
                endcase
            end

            // -------------------------
            // Read path with access control (CWE-1262, CWE-1256)
            // -------------------------
            if (reg_ren) begin
                case (reg_addr)
                    // 0: security configuration (privileged read-only)
                    3'h0: begin
                        if (priv_can_read_sec_cfg) begin
                            reg_rdata <= security_config_reg;
                        end else begin
                            reg_rdata <= 32'hDEAD_DEAD; // fault / masked
                        end
                    end

                    // 1: crypto key (write-only: mask reads)
                    3'h1: begin
                        if (priv_can_read_key) begin
                            // Optionally mask key to 0 for all software:
                            reg_rdata <= 32'h0000_0000;
                        end else begin
                            reg_rdata <= 32'hDEAD_DEAD;
                        end
                    end

                    // 2: status (readable by all)
                    3'h2: begin
                        if (can_read_status) begin
                            reg_rdata <= status_reg;
                        end else begin
                            reg_rdata <= 32'hDEAD_DEAD;
                        end
                    end

                    // 3: version (read-only, all)
                    3'h3: begin
                        if (can_read_version) begin
                            reg_rdata <= version_reg;
                        end else begin
                            reg_rdata <= 32'hDEAD_DEAD;
                        end
                    end

                    // 4: security lock status (privileged read)
                    3'h4: begin
                        if (privileged) begin
                            reg_rdata <= {31'b0, security_lock};
                        end else begin
                            reg_rdata <= 32'hDEAD_DEAD;
                        end
                    end

                    default: reg_rdata <= 32'hDEAD_DEAD;
                endcase
            end
        end
    end

endmodule
