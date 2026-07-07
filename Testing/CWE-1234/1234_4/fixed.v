module test_secure (
    input  wire        clk,
    input  wire        rst_n,        // active-low reset
    input  wire        lock_set,     // hardware-derived signal to set lock (write-once)
    input  wire        debug,        // debug indication (cannot override lock)
    input  wire        write_en,     // software write enable
    input  wire        priv_ok,      // hardware privilege check (1 = privileged)
    input  wire [7:0]  data_in,
    output reg  [7:0]  lock_bits,
    output reg         lock          // internal lock bit, write-once
);

    // Reset and lock behavior:
    // - lock_bits scrubbed on reset
    // - lock is cleared on reset, then can be set once via lock_set
    // - once lock=1, it never goes back to 0
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            lock_bits <= 8'h00;   // CWE-226: scrub on reset
            lock      <= 1'b0;
        end else begin
            // Write-once lock bit (CWE-1234 / CWE-1262)
            if (lock_set && !lock)
                lock <= 1'b1;

            // Debug cannot override lock; debug only allowed when lock is already set
            // Writes allowed only when:
            //  - lock is set
            //  - privilege check passes
            //  - write_en is asserted
            if (write_en && lock && priv_ok) begin
                lock_bits <= data_in;
            end

            // Optional: scrub sensitive register when entering debug mode
            // (CWE-226, CWE-1191)
            if (debug && !priv_ok) begin
                // entering unauthenticated debug: clear sensitive contents
                lock_bits <= 8'h00;
            end
        end
    end

endmodule
