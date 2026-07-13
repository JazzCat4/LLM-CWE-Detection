// https://cwe.mitre.org/data/definitions/1256.html
// A privileged hardware feature is controlled by a memory mapped register
// The interface does not check privilege level, allowing unprivileged software to enable it

module cwe1256(
    input wire clk,
    input wire reset,

    // Software-visible register interface
    input wire sw_we,
    input wire [3:0] sw_addr,
    input wire [31:0] sw_wdata,
    output reg [31:0] sw_rdata,

    // Privilege indicator (1 = priv.)
    input wire sw_privileged,

    // Hardware feature output
    output reg accel_enable // controls secure accelerator
);

// Memory mapped register
localparam ADDR_CTRL = 4'h0;

// Control register (bit 0 = enable accelerator)
reg [31:0] ctrl_reg;

always @(posedge clk or posedge reset) begin
    if (reset) begin
        ctrl_reg <= 32'h0;
        accel_enable <= 1'b0;
    end else begin
        // No privilege check on writes to ctrl_reg.
        // Unprivileged software can enable secure hardware features.
        if (sw_we && sw_addr == ADDR_CTRL) begin
            ctrl_reg <= sw_wdata;
        end

        // Hardware feature controlled directly by software register
        accel_enable <= ctrl_reg[0];
    end
end

// Read path
always @(*) begin
    case(sw_addr)
    ADDR_CTRL: sw_rdata = ctrl_reg;
    default: sw_rdata = 32'hDEADBEEF;
    endcase
end

endmodule