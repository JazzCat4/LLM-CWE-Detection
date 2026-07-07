`include "1234_5.v"

`timescale 1ns/1ps

module test_tb;
    reg        clk;
    reg        resetn;
    reg        write_en;
    reg  [7:0] data_in;
    reg        lock_set;
    reg        debug_enable;
    wire [7:0] data_out;

    // DUT
    test dut (
        .clk(clk),
        .resetn(resetn),
        .write_en(write_en),
        .data_in(data_in),
        .lock_set(lock_set),
        .debug_enable(debug_enable),
        .data_out(data_out)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;  // 100 MHz nominal
    end

    // Stimulus
    initial begin
        // Initialize
        resetn       = 0;
        write_en     = 0;
        data_in      = 8'h00;
        lock_set     = 0;
        debug_enable = 0;

        // Global reset (CWE-226: check scrub on reset)
        #12;
        resetn = 1;
        #10;

        // ------------------------------------------------------------
        // 1) CWE-1262 / CWE-1234: Lock bit and debug override
        // ------------------------------------------------------------

        // Write sensitive value before lock
        write_en = 1;
        data_in  = 8'hAA;   // pretend secret
        #10;                // posedge clk
        write_en = 0;
        #10;

        // Lock the register
        lock_set = 1;
        #10;                // posedge clk
        lock_set = 0;
        #10;

        // Attempt normal write while locked (should be blocked)
        write_en = 1;
        data_in  = 8'h55;
        #10;                // posedge clk
        write_en = 0;
        #10;

        // Check: data_out should still be 8'hAA if lock works
        $display("After locked normal write, data_out = 0x%0h (expect 0xAA)", data_out);

        // Enable debug and attempt write while locked (CWE-1234: override)
        debug_enable = 1;
        write_en     = 1;
        data_in      = 8'h33;
        #10;                // posedge clk
        write_en     = 0;
        #10;

        // Check: data_out changed despite lock (vulnerability)
        $display("With debug_enable=1 while locked, data_out = 0x%0h (expect 0x33, shows lock bypass)", data_out);

        // ------------------------------------------------------------
        // 2) CWE-1262 / CWE-1256: Unprivileged access to sensitive register
        // ------------------------------------------------------------

        // Model "unprivileged" software by simply driving inputs
        // No privilege check exists; any agent can do this.

        debug_enable = 0;
        write_en     = 1;
        data_in      = 8'hF0;  // untrusted write
        #10;
        write_en     = 0;
        #10;

        $display("Unprivileged write to data_out = 0x%0h (no access control present)", data_out);

        // ------------------------------------------------------------
        // 3) CWE-1247: Clock / reset glitch sensitivity
        // ------------------------------------------------------------

        // Put a known sensitive value
        write_en = 1;
        data_in  = 8'hC3;
        #10;
        write_en = 0;
        #10;

        // Asynchronous reset glitch: brief low pulse
        $display("Injecting resetn glitch...");
        resetn = 0;  // glitch
        #2;          // shorter than full cycle
        resetn = 1;
        #10;

        $display("After resetn glitch, locked=%b, data_out=0x%0h (check for unintended clear/unlock)", dut.locked, data_out);

        // ------------------------------------------------------------
        // 4) CWE-226: Resource reuse / scrubbing behavior
        // ------------------------------------------------------------

        // Assume data_out holds a secret (0x5A)
        write_en = 1;
        data_in  = 8'h5A;
        #10;
        write_en = 0;
        #10;

        $display("Secret written, data_out = 0x%0h", data_out);

        // "Context switch": change to new value without explicit scrub
        write_en = 1;
        data_in  = 8'h0F;
        #10;
        write_en = 0;
        #10;

        $display("After reuse without explicit scrub, data_out = 0x%0h (old secret overwritten, but no scrub semantics)", data_out);

        // Final reset to check zeroing
        resetn = 0;
        #10;
        resetn = 1;
        #10;

        $display("After full reset, data_out = 0x%0h (expect 0x00 for scrub)", data_out);

        $finish;
    end
endmodule
