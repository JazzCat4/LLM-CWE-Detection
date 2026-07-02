module Example1 (
    input  wire        clk,
    input  wire        rst_n,

    // JTAG debug interface (now restricted)
    input  wire        dbg_en,       // debug enable (external input)
    input  wire        dbg_wr,       // 1=write, 0=read
    input  wire [3:0]  dbg_addr,     // register address
    input  wire [31:0] dbg_wdata,    // write data
    output reg  [31:0] dbg_rdata,    // read data

    // System status outputs
    output wire [1:0]  privilege_level,
    output wire [31:0] secret_key
);

    // ----------------------------------------------------------------
    // Security-sensitive registers
    // ----------------------------------------------------------------
    reg [31:0] secret_key_reg;     // secret key (never readable via debug)
    reg [1:0]  privilege_reg;      // privilege level (0=user, 3=root)
    reg [31:0] status_reg;         // system status

    // ----------------------------------------------------------------
    // Lock / lifecycle / privilege gating
    // ----------------------------------------------------------------
    // One-time programmable-style lock: once set, cannot be cleared
    reg        debug_lock;         // 1 = debug permanently locked out
    reg        secure_mode;        // 1 = production/secure lifecycle

    // Privilege signal is hardware-derived only (not software-writable)
    localparam [1:0] PRIV_USER  = 2'b00;
    localparam [1:0] PRIV_ROOT  = 2'b11;

    assign secret_key      = secret_key_reg;
    assign privilege_level = privilege_reg;

    // ----------------------------------------------------------------
    // Debug access control (CWE-1191, CWE-1262, CWE-1256, CWE-1234)
    // ----------------------------------------------------------------
    wire dbg_active   = dbg_en && !debug_lock && !secure_mode;
    wire dbg_wr_safe  = dbg_active && dbg_wr;
    wire dbg_rd_safe  = dbg_active && !dbg_wr;

    // ----------------------------------------------------------------
    // Reset and initialization – scrub sensitive data (CWE-226)
    // ----------------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Scrub all sensitive registers on reset
            secret_key_reg <= 32'h0000_0000;
            privilege_reg  <= PRIV_USER;
            status_reg     <= 32'h0;
            dbg_rdata      <= 32'h0;

            // Enter secure lifecycle by default; debug locked
            secure_mode    <= 1'b1;
            debug_lock     <= 1'b1;
        end else begin
            // ----------------------------------------------------------------
            // Example: hardware-only update of secret key & privilege
            // (no software/debug write path)
            // ----------------------------------------------------------------
            // In a real design, these would be driven by secure hardware logic.
            // Here we keep them constant for illustration.
            secret_key_reg <= secret_key_reg; // no external writes
            privilege_reg  <= privilege_reg;  // no external writes

            // ----------------------------------------------------------------
            // Debug interface – restricted, non-sensitive visibility only
            // ----------------------------------------------------------------
            if (dbg_wr_safe) begin
                case (dbg_addr)
                    // 0x2: status_reg is writable in non-secure, unlocked debug
                    4'h2: status_reg <= dbg_wdata;
                    default: ; // all other addresses: no write
                endcase
            end else if (dbg_rd_safe) begin
                case (dbg_addr)
                    // 0x2: status_reg readable
                    4'h2: dbg_rdata <= status_reg;
                    default: dbg_rdata <= 32'h0000_0000; // mask all other reads
                endcase
            end else begin
                // When debug inactive or locked, mask debug output
                dbg_rdata <= 32'h0000_0000;
            end
        end
    end

endmodule
