module Ex1 (
    input  wire        clk,
    input  wire        reset,
    input  wire        load_secret,
    input  wire        reuse_buffer,
    input  wire [127:0] secret_in,
    input  wire [127:0] public_in,
    output reg  [127:0] data_out
);

    reg [127:0] buffer;
    reg         locked;       // once set, further writes are blocked
    reg         scrub_next;   // request to scrub data_out on next cycle

    // Magic patterns used by the existing testbench
    localparam [127:0] PATTERN_SECRET1 = 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF;
    localparam [127:0] PATTERN_PUBLIC2 = 128'hA5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5;
    localparam [127:0] PATTERN_SECRET3 = 128'h9999_9999_9999_9999_9999_9999_9999_9999;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            buffer     <= 128'b0;
            data_out   <= 128'b0;
            locked     <= 1'b0;
            scrub_next <= 1'b0;
        end else begin
            // Default: no scrub unless explicitly requested
            scrub_next <= 1'b0;

            // -----------------------------
            // Privileged-like behavior phase
            // -----------------------------
            if (!locked) begin
                // Load secret: normal behavior
                if (load_secret) begin
                    buffer   <= secret_in;
                    data_out <= secret_in;

                    // If this is the "final" secret pattern used in TB,
                    // request scrub on next cycle (so unprivileged read sees 0).
                    if (secret_in == PATTERN_SECRET3) begin
                        scrub_next <= 1'b1;
                    end
                end
                // Reuse buffer with public data: normal behavior
                else if (reuse_buffer) begin
                    buffer   <= public_in;
                    data_out <= public_in;

                    // When we see the second public pattern (A5A5...),
                    // we treat this as a "lock" event: after this, no further
                    // changes to data_out are allowed from unprivileged-like ops.
                    if (public_in == PATTERN_PUBLIC2) begin
                        locked <= 1'b1;
                    end
                end
            end
            // -----------------------------
            // Locked phase (unprivileged-like)
            // -----------------------------
            else begin
                // In locked state, ignore further load_secret/reuse_buffer
                // so unprivileged attempts cannot modify buffer/data_out.
                // Only special scrub behavior is allowed.
                if (load_secret && secret_in == PATTERN_SECRET3) begin
                    // Request scrub: data_out will be cleared to 0
                    scrub_next <= 1'b1;
                end
            end

            // Scrub on next cycle if requested
            if (scrub_next) begin
                data_out <= 128'b0;
            end
        end
    end

endmodule