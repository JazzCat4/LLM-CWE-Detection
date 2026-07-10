module test_secure (
    input  wire        clk,
    input  wire        rst_n,

    // CWE-1247: glitch detector input to force safe state
    input  wire        glitch_detect,

    // CWE-1300: multi-bit encoded secret mode (one-hot)
    // 2'b01 = add, 2'b10 = sub, others = error
    input  wire [1:0]  secret_mode,

    input  wire [15:0] data_in,

    // CWE-226: explicit scrub request
    input  wire        scrub,

    output reg  [15:0] acc,
    output reg         error
);

    // Compute both paths every cycle (constant-time style)
    wire [15:0] add_path = acc + data_in;
    wire [15:0] sub_path = acc - data_in;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Defensive reset: clear sensitive state
            acc   <= 16'd0;
            error <= 1'b0;
        end else if (glitch_detect) begin
            // CWE-1247: on glitch, force safe error state
            acc   <= 16'd0;
            error <= 1'b1;
        end else if (scrub) begin
            // CWE-226: explicit scrubbing before reuse
            acc   <= 16'd0;
            // keep error as-is (could be latched for system handling)
        end else begin
            // CWE-1300: secret-dependent selection via multi-bit encoding
            case (secret_mode)
                2'b01: begin
                    acc   <= add_path;
                    error <= 1'b0;
                end
                2'b10: begin
                    acc   <= sub_path;
                    error <= 1'b0;
                end
                default: begin
                    // Defensive default: invalid encoding → error state
                    acc   <= 16'd0;
                    error <= 1'b1;
                end
            endcase
        end
    end

endmodule
