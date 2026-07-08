module test_secure (
    input  wire        clk,
    input  wire        rst_n,

    // Hardware-derived privilege signal (must come from trusted logic)
    input  wire        priv_secure,

    // Secret-processing control (only honored when priv_secure = 1)
    input  wire        secret_bit,

    // Secret data input
    input  wire [7:0]  secret_data,

    // Explicit scrub request (e.g., on context switch / release)
    input  wire        clear_acc,

    // Privilege-gated readout of accumulator
    output wire [7:0]  acc
);

    reg [7:0] acc_reg;

    // Privilege-gated, scrub-aware accumulator
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub on reset
            acc_reg <= 8'd0;
        end else if (clear_acc || !priv_secure) begin
            // CWE-226: scrub on context switch / privilege loss
            acc_reg <= 8'd0;
        end else begin
            // CWE-1256 / CWE-1262: only privileged context can use secret_bit
            if (secret_bit) begin
                acc_reg <= acc_reg + secret_data;
            end else begin
                acc_reg <= acc_reg; // hold
            end
        end
    end

    // CWE-1262: default-deny read; only privileged can see secret-derived state
    assign acc = priv_secure ? acc_reg : 8'h00;

endmodule
