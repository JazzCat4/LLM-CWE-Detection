module Ex1_secure(
    input  wire        clk,
    input  wire        reset,

    // Software-visible register interface
    input  wire        sw_we,
    input  wire [3:0]  sw_addr,
    input  wire [31:0] sw_wdata,
    output reg  [31:0] sw_rdata,

    // Privilege indicator (1 = priv.)
    input  wire        sw_privileged,

    // Hardware feature output
    output reg         accel_enable // controls secure accelerator
);

    // Memory mapped registers
    localparam ADDR_CTRL = 4'h0; // control register
    localparam ADDR_LOCK = 4'h1; // lock register

    // Control register (bit 0 = enable accelerator)
    reg [31:0] ctrl_reg;

    // Lock register: bit 0 = write-once lock for ctrl_reg
    reg        ctrl_lock;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            // CWE-226: scrub sensitive state on reset
            ctrl_reg     <= 32'h0;
            accel_enable <= 1'b0;
            ctrl_lock    <= 1'b0;
        end else begin
            // CWE-226: scrub when privilege is lost
            if (!sw_privileged) begin
                ctrl_reg     <= 32'h0;
                accel_enable <= 1'b0;
                // lock remains set if previously locked
            end else begin
                // CWE-1262 / CWE-1256: privilege-gated, lock-gated writes
                if (sw_we) begin
                    case (sw_addr)
                        ADDR_CTRL: begin
                            if (!ctrl_lock) begin
                                // Only privileged, unlocked context can modify ctrl_reg
                                ctrl_reg <= sw_wdata & 32'h0000_0001; // mask to used bits
                            end
                        end
                        ADDR_LOCK: begin
                            // Write-once lock: once set, cannot be cleared
                            if (!ctrl_lock && sw_wdata[0])
                                ctrl_lock <= 1'b1;
                        end
                        default: begin
                            // ignore writes to other addresses
                        end
                    endcase
                end

                // Hardware feature controlled by privileged, locked CSR
                accel_enable <= ctrl_reg[0];
            end
        end
    end

    // Read path with access control
    always @(*) begin
        // CWE-1262: default-deny for sensitive CSRs
        sw_rdata = 32'h0000_0000;

        if (sw_privileged) begin
            case (sw_addr)
                ADDR_CTRL: sw_rdata = ctrl_reg;
                ADDR_LOCK: sw_rdata = {31'b0, ctrl_lock};
                default:   sw_rdata = 32'hDEADBEEF;
            endcase
        end
        // Unprivileged reads see zeros for sensitive registers
    end

endmodule
