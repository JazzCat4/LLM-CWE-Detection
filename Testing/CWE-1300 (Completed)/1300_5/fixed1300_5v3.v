// Hardened module: strict scrub, privilege gating, and edge-triggered secret use
module test_secure (
    input  wire        clk,
    input  wire        rst_n,

    // Hardware-derived privilege signal (trusted)
    input  wire        priv_secure,

    // Secret-processing control (only effective when priv_secure = 1)
    input  wire        secret_bit,

    // Secret data input
    input  wire [7:0]  secret_data,

    // Explicit scrub request (on context switch / release)
    input  wire        clear_acc,

    // Privilege-gated readout of accumulator
    output wire [7:0]  acc
);

    reg [7:0] acc_reg;
    reg       secret_bit_d;
    reg       reset_armed;  // blocks accumulation for first cycle after reset

    // Track previous secret_bit for edge detection
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            secret_bit_d <= 1'b0;
        else
            secret_bit_d <= secret_bit;
    end

    wire secret_rise = secret_bit & ~secret_bit_d;

    // Privilege-gated, scrub-aware accumulator
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub on reset and disarm accumulation
            acc_reg     <= 8'd0;
            reset_armed <= 1'b0;
        end else begin
            // Arm after first post-reset cycle
            if (!reset_armed)
                reset_armed <= 1'b1;

            // Scrub on explicit clear or loss of privilege
            if (clear_acc || !priv_secure) begin
                acc_reg <= 8'd0;
            end else if (priv_secure && reset_armed && secret_rise) begin
                // CWE-1256 / CWE-1262: only privileged, armed, edge-triggered secret use
                acc_reg <= acc_reg + secret_data;
            end else begin
                acc_reg <= acc_reg; // hold
            end
        end
    end

    // CWE-1262: default-deny read; only privileged can see secret-derived state
    assign acc = priv_secure ? acc_reg : 8'h00;

endmodule
