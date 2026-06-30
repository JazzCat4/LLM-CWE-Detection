// ============================================================
// CWE-1262: Improper Access Control for Register Interface
// File: cwe1262_fixed.v   <= FIXED VERSION
//
// Fix:
//   Replace the broken `user_mode` check with a correct check
//   on `cpu_privilege_level`.
//   In RISC-V / ARM convention:
//     cpu_privilege_level == 2'b11 → Machine/Privileged mode
//     cpu_privilege_level == 2'b01 → User/Unprivileged mode
//
//   Only machine-mode (privileged) code may access addr 0–1.
//   User-mode reads return a safe placeholder (0xDEAD_DEAD).
//   User-mode writes to privileged registers are silently dropped.
// ============================================================

module periph_regs_fixed (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        reg_wen,
    input  wire        reg_ren,
    input  wire [2:0]  reg_addr,
    input  wire [31:0] reg_wdata,
    output reg  [31:0] reg_rdata,

    input  wire [1:0]  cpu_privilege_level, // 2'b11=machine, 2'b01=user
    input  wire        user_mode,           // kept for interface compatibility

    output wire [31:0] crypto_key,
    output wire [31:0] security_config
);

    reg [31:0] security_config_reg;
    reg [31:0] crypto_key_reg;
    reg [31:0] status_reg;
    reg [31:0] version_reg;

    assign security_config = security_config_reg;
    assign crypto_key      = crypto_key_reg;

    // FIX: check the correct signal — cpu_privilege_level
    // Machine mode = 2'b11 (privileged), User mode = 2'b01
    wire priv_ok = (cpu_privilege_level == 2'b11);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            security_config_reg <= 32'hA5A5_0001;
            crypto_key_reg      <= 32'hDEAD_BEEF;
            status_reg          <= 32'h0000_0000;
            version_reg         <= 32'h0000_0100;
            reg_rdata           <= 32'h0;
        end else begin
            // ---------- WRITE ----------
            if (reg_wen) begin
                case (reg_addr)
                    // FIX: priv_ok now correctly reflects cpu_privilege_level
                    3'h0: if (priv_ok) security_config_reg <= reg_wdata;
                    3'h1: if (priv_ok) crypto_key_reg      <= reg_wdata;
                    3'h2: status_reg <= reg_wdata;
                    default: ;
                endcase
            end

            // ---------- READ ----------
            if (reg_ren) begin
                case (reg_addr)
                    3'h0: reg_rdata <= (priv_ok) ? security_config_reg : 32'hDEAD_DEAD;
                    3'h1: reg_rdata <= (priv_ok) ? crypto_key_reg      : 32'hDEAD_DEAD;
                    3'h2: reg_rdata <= status_reg;
                    3'h3: reg_rdata <= version_reg;
                    default: reg_rdata <= 32'hDEAD_DEAD;
                endcase
            end
        end
    end

endmodule
