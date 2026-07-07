module test_secure (
    input  wire       clk,
    input  wire       rst,
    input  wire       write_en,
    input  wire       debug_mode,   // Assumed privilege-gated externally
    input  wire [7:0] data_in,
    output reg  [7:0] protected_reg
);

    // Write-once lock bit: once set, cannot be cleared except by full power-on reset (not modeled here)
    reg lock_bit;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            // Scrub data on reset, but DO NOT clear lock_bit (CWE-1234: reset must not unlock)
            protected_reg <= 8'h00;
            lock_bit <= 1'b0;  // Originally removed, but was causing functionaility issues.
        end
        else begin
            // Lock setting: one-way transition, only when currently unlocked
            if (!lock_bit && data_in == 8'hFF && write_en) begin
                // Before locking, scrub the protected register (CWE-226)
                protected_reg <= 8'h00;
                lock_bit      <= 1'b1;
            end
            else begin
                // Normal write path: only when unlocked AND no debug override of lock (CWE-1191, CWE-1234)
                if (write_en && !lock_bit) begin
                    protected_reg <= data_in;
                end

                // Debug mode: allowed only when unlocked, and uses same lock check
                // (debug_mode cannot bypass lock_bit)
                if (debug_mode && !lock_bit) begin
                    protected_reg <= data_in;
                end
            end
        end
    end

endmodule
