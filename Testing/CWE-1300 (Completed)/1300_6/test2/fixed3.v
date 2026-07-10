module test_secure_final (
    input  wire        clk,
    input  wire        rst_n,

    // CWE-1247: glitch detector input to force and latch safe error state
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

    // Latched fault and scrub states
    reg faulted;
    reg scrubbed;

    // Constant-time style: compute both paths every cycle
    wire [15:0] add_path = acc + data_in;
    wire [15:0] sub_path = acc - data_in;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Strong reset: clear everything
            acc      <= 16'd0;
            error    <= 1'b0;
            faulted  <= 1'b0;
            scrubbed <= 1'b0;
        end else begin
            // Highest priority: glitch detection
            if (glitch_detect) begin
                acc      <= 16'd0;
                error    <= 1'b1;
                faulted  <= 1'b1;
                scrubbed <= 1'b0;
            end
            // Next: explicit scrub
            else if (scrub) begin
                acc      <= 16'd0;
                scrubbed <= 1'b1;
                // keep error/faulted as-is
            end
            // If faulted, stay in error state until reset
            else if (faulted) begin
                acc   <= 16'd0;
                error <= 1'b1;
            end
            // If scrubbed, keep acc cleared until reset
            else if (scrubbed) begin
                acc <= 16'd0;
                // error unchanged
            end
            // Normal operation
            else begin
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
                        acc   <= 16'd0;
                        error <= 1'b1;
                    end
                endcase
            end
        end
    end

endmodule
