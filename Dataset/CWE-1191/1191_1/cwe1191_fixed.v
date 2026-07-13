// ============================================================
// CWE-1191: On-Chip Debug and Test Interface With Improper
//           Access Control
// File: CWE1191_fixed.v  ← Fixed version
//
// Fix strategy:
//   1. Introduce a lifecycle register (pre-production vs. production)
//   2. Debug interface is only open during DEVELOPMENT phase
//   3. In production phase (PROD_LOCKED), debug interface is permanently disabled
//   4. Even when debug is open, secret_key cannot be read via debug
//   5. Privilege register can only be lowered, not raised via debug
// ============================================================

module jtag_debug_ctrl_fixed (
    input  wire        clk,
    input  wire        rst_n,

    // JTAG debug interface
    input  wire        dbg_en,
    input  wire        dbg_wr,
    input  wire [3:0]  dbg_addr,
    input  wire [31:0] dbg_wdata,
    output reg  [31:0] dbg_rdata,

    // Lifecycle control (driven by fuse/OTP, hardened after manufacturing)
    input  wire [1:0]  lifecycle,    // 2'b00=DEV, 2'b11=PROD_LOCKED

    // System status outputs
    output wire [1:0]  privilege_level,
    output wire [31:0] secret_key
);

    // Lifecycle constants
    localparam LC_DEV         = 2'b00;  // Development phase: debug allowed
    localparam LC_PROD_LOCKED = 2'b11;  // Production locked: debug permanently disabled

    // Internal security-sensitive registers
    reg [31:0] secret_key_reg;
    reg [1:0]  privilege_reg;
    reg [31:0] status_reg;

    assign secret_key      = secret_key_reg;
    assign privilege_level = privilege_reg;

    // FIX 1: debug interface is only active during development phase
    wire debug_allowed = (lifecycle == LC_DEV) && dbg_en;

    // FIX 2: secret_key address is masked in the debug interface (never readable)
    wire addr_is_secret = (dbg_addr == 4'h0);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            secret_key_reg <= 32'hDEADBEEF;
            privilege_reg  <= 2'b00;
            status_reg     <= 32'h0;
            dbg_rdata      <= 32'h0;
        end else if (debug_allowed) begin   // FIX 1: this branch is never entered in production

            if (dbg_wr) begin
                case (dbg_addr)
                    // FIX 2: writes to secret_key are also blocked (by omitting addr 0x0)
                    // 4'h0 is intentionally not listed; attacker writes to secret_key have no effect

                    // FIX 3: privilege can only be lowered (escalation via debug is blocked)
                    4'h1: begin
                        // Only accept values less than or equal to the current privilege level
                        if (dbg_wdata[1:0] <= privilege_reg)
                            privilege_reg <= dbg_wdata[1:0];
                        // Attempted escalation → silently ignored
                    end
                    4'h2: status_reg <= dbg_wdata;
                    default: ;
                endcase
            end else begin
                case (dbg_addr)
                    // FIX 2: secret_key address returns all-zero placeholder; real value is not leaked
                    4'h0: dbg_rdata <= 32'h0000_0000; // Masked — real key is not returned
                    4'h1: dbg_rdata <= {30'h0, privilege_reg};
                    4'h2: dbg_rdata <= status_reg;
                    default: dbg_rdata <= 32'hDEAD_DEAD;
                endcase
            end

        end else begin
            // FIX 4: when debug is not allowed, reads return a fixed error value
            dbg_rdata <= 32'hFFFF_FFFF;  // Indicates debug is locked
        end
    end

endmodule

// ============================================================
// Fixed attack scenarios (simulation):
//
// Scenario A: Read secret_key in production environment
//   lifecycle = 2'b11 (PROD_LOCKED)
//   dbg_en = 1, dbg_addr = 4'h0
//   → dbg_rdata = 32'hFFFF_FFFF (locked; key is not leaked)
//
// Scenario B: Attempt to read secret_key in development environment
//   lifecycle = 2'b00 (DEV)
//   dbg_en = 1, dbg_addr = 4'h0
//   → dbg_rdata = 32'h0 (address is masked; key is still not leaked)
//
// Scenario C: Attempt privilege escalation via debug
//   lifecycle = 2'b00 (DEV)
//   dbg_wr = 1, dbg_addr = 4'h1, dbg_wdata = 32'h3
//   privilege_reg currently = 2'b00
//   → 3 > 0, write is silently ignored, privilege unchanged
// ============================================================
