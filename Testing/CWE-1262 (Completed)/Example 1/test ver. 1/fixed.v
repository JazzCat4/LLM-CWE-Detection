module periph_regs_secure (
    input  wire        clk,
    input  wire        rst_n,

    // SW-visible register interface
    input  wire        reg_wen,
    input  wire        reg_ren,
    input  wire [2:0]  reg_addr,
    input  wire [31:0] reg_wdata,
    output reg  [31:0] reg_rdata,

    // Hardware-derived privilege signals (not SW-writable)
    input  wire [1:0]  cpu_privilege_level, // 2'b11 = highest privilege
    input  wire        user_mode,           // 1 = user, 0 = supervisor

    // Environmental monitor (glitch detection)
    input  wire        env_ok,              // 1 = voltage/clock in spec

    // Outputs to other hardware blocks (crypto engine, security logic)
    output wire [31:0] crypto_key,
    output wire [31:0] security_config
);

    // Security-critical registers
    reg [31:0] security_config_reg;  // security configuration CSR
    reg [31:0] crypto_key_reg;       // secret key (hardware-only)
    reg [31:0] status_reg;           // status / lifecycle
    reg [31:0] version_reg;          // version / ID

    // Write-once lock bit for security configuration
    reg        sec_lock_reg;         // 1 = locked, only reset can clear

    // Boot / configuration state
    reg        boot_done;            // hardware control locked after boot

    // Assign outputs
    assign security_config = security_config_reg;

    // Secret key is visible to hardware, but SW cannot read via reg_rdata
    assign crypto_key = crypto_key_reg;

    // --------------------------------------------------------------------
    // Privilege and access control
    // --------------------------------------------------------------------

    // Hardware-derived privilege: highest level, not user mode
    wire is_privileged = (cpu_privilege_level == 2'b11) && (user_mode == 1'b0);

    // Effective privilege OK: must be privileged AND environment OK
    // Default-deny: if env_ok is low or privilege is low, access is denied.
    wire priv_ok = is_privileged && env_ok;

    // --------------------------------------------------------------------
    // Reset and initialization
    // --------------------------------------------------------------------
    // All security-critical registers have explicit reset values.
    // Security controls reset to most restrictive state:
    //  - security_config_reg = 0 (all features disabled)
    //  - crypto_key_reg      = 0 (no secret material)
    //  - sec_lock_reg        = 0 (unlocked, but will be locked after boot)
    //  - boot_done           = 0 (hardware control not yet locked)
    // --------------------------------------------------------------------

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            security_config_reg <= 32'h0000_0000; // restrictive default
            crypto_key_reg      <= 32'h0000_0000; // secrets zeroed
            status_reg          <= 32'h0000_0000;
            version_reg         <= 32'h0000_0100; // same version as before
            sec_lock_reg        <= 1'b0;
            boot_done           <= 1'b0;
            reg_rdata           <= 32'h0000_0000;
        end else begin
            // ----------------------------------------------------------------
            // Write path (SW-visible)
            // ----------------------------------------------------------------
            if (reg_wen) begin
                case (reg_addr)
                    // 0: security configuration CSR
                    //    - write allowed only if privileged AND not locked
                    //    - once locked, only reset can clear sec_lock_reg
                    3'h0: begin
                        if (priv_ok && !sec_lock_reg) begin
                            security_config_reg <= reg_wdata;
                        end
                    end

                    // 1: crypto key register (secret)
                    //    - write allowed only if privileged
                    //    - write-only from SW perspective (reads masked)
                    //    - key is scrubbed (zeroed) when lock is set or on reset
                    3'h1: begin
                        $display("cpu_privilege_level: %h", cpu_privilege_level);
                        $display("user_mode: %h", user_mode);
                        $display("(cpu_privilege_level == 2'b11) && (user_mode == 1'b0): %h", (cpu_privilege_level == 2'b11) && (user_mode == 1'b0));
                        $display("is_privileged: %h", is_privileged);
                        if (priv_ok) begin
                            
                            crypto_key_reg <= reg_wdata;
                        end
                    end

                    // 2: status register
                    //    - may contain lifecycle info; privileged write only
                    //    - can be used to signal boot completion
                    3'h2: begin
                        if (priv_ok) begin
                            status_reg <= reg_wdata;
                            // Example: bit 0 indicates boot_done
                            if (reg_wdata[0]) begin
                                boot_done <= 1'b1;
                            end
                        end
                    end

                    // 3: lock control (write-once lock bit)
                    //    - privileged-only
                    //    - once sec_lock_reg is set, cannot be cleared except reset
                    3'h3: begin
                        if (priv_ok && !sec_lock_reg) begin
                            if (reg_wdata[0]) begin
                                sec_lock_reg <= 1'b1;
                                // Scrub secrets on lock: zero key
                                crypto_key_reg <= 32'h0000_0000;
                            end
                        end
                    end

                    default: begin
                        // Default: deny writes to unmapped addresses
                        // No side effects
                    end
                endcase
            end

            // ----------------------------------------------------------------
            // Read path (SW-visible)
            // ----------------------------------------------------------------
            if (reg_ren) begin
                case (reg_addr)
                    // 0: security configuration CSR
                    //    - readable only if privileged AND environment OK
                    //    - otherwise return masked value (0)
                    3'h0: begin
                        if (priv_ok) begin
                            reg_rdata <= security_config_reg;
                        end else begin
                            reg_rdata <= 32'h0000_0000; // masked
                        end
                    end

                    // 1: crypto key register (secret)
                    //    - write-only: reads always return 0
                    3'h1: begin
                        reg_rdata <= 32'h0000_0000; // masked, regardless of privilege
                    end

                    // 2: status register
                    //    - readable by any mode (status is non-secret)
                    3'h2: begin
                        reg_rdata <= status_reg;
                    end

                    // 3: version register
                    //    - readable by any mode
                    3'h3: begin
                        reg_rdata <= version_reg;
                    end

                    // Default: deny access to unmapped addresses
                    //          return a safe value (0) rather than leaking data
                    default: begin
                        reg_rdata <= 32'h0000_0000;
                    end
                endcase
            end
        end
    end

endmodule
