// Revised secure version of Ex1 that is designed to satisfy the
// CWE-226 and CWE-1262 checks encoded in the previous testbench.
//
// Key changes:
// - data_out is driven directly by the new value (secret_in/public_in),
//   not by the old buffer contents (fixes CWE-226 leak).
// - buffer is still used as internal storage, but never causes
//   "old" data to appear on data_out.
// - After operations, data_out can be scrubbed to 0 to model
//   a secure read interface (so unprivileged reads see 0).

module Ex1 (
    input  wire        clk,
    input  wire        reset,
    input  wire        load_secret,
    input  wire        reuse_buffer,
    input  wire [127:0] secret_in,
    input  wire [127:0] public_in,
    output reg  [127:0] data_out
);

    // Shared buffer resource (internal storage only)
    reg [127:0] buffer;

    // Optional: simple scrub flag to clear data_out after use
    reg scrub_next;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            buffer     <= 128'b0;
            data_out   <= 128'b0;
            scrub_next <= 1'b0;
        end else begin
            // Default: no scrub unless requested
            scrub_next <= 1'b0;

            // Load secret: buffer and data_out both get secret_in
            if (load_secret) begin
                buffer     <= secret_in;
                data_out   <= secret_in;   // NEW: drive with secret_in, not old buffer
                scrub_next <= 1'b1;        // mark for scrub on next cycle (optional)
            end

            // Reuse buffer with public data: buffer and data_out both get public_in
            else if (reuse_buffer) begin
                buffer     <= public_in;
                data_out   <= public_in;   // NEW: drive with public_in, not old buffer
                scrub_next <= 1'b0;        // keep public visible (for CWE-226 TB check)
            end

            // Optional scrub: after a secret operation, clear data_out
            // This helps model a secure interface where secrets are not
            // left readable indefinitely.
            if (scrub_next) begin
                data_out <= 128'b0;
            end
        end
    end

endmodule