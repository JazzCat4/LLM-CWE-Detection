module secure_test (
    input        clk,
    input        resetn,
    input        write_en,
    input  [7:0] data_in,
    input        lock_set,
    input        debug_enable,   // no longer allowed to bypass lock
    input        privileged,     // hardware-derived privilege level
    input        glitch_detect,  // from glitch detector
    output reg [7:0] data_out
);
    reg locked;

    // Single sequential block: reset, glitch handling, lock, and writes
    always @(posedge clk or negedge resetn) begin
        if (!resetn) begin
            // CWE-226: scrub on reset
            locked   <= 1'b0;
            data_out <= 8'h00;
        end else if (glitch_detect) begin
            // CWE-1247: fail-closed on glitch
            locked   <= 1'b1;      // force locked
            data_out <= 8'h00;     // scrub data
        end else begin
            // CWE-1262 / CWE-1256: privilege-gated lock
            // Write-once lock bit, only privileged can set
            if (privileged && lock_set && !locked)
                locked <= 1'b1;

            // CWE-1262 / CWE-1256: privilege-gated writes, default-deny
            // No debug override of lock (CWE-1234)
            if (privileged && write_en && !locked)
                data_out <= data_in;

            // debug_enable may be used for non-security-critical behavior
            // but MUST NOT bypass lock or privilege checks.
        end
    end
endmodule
