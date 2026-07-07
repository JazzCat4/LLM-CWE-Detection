`include "fixed.v"

`timescale 1ns/1ps

module secure_test_tb;
    reg        clk;
    reg        resetn;
    reg        write_en;
    reg  [7:0] data_in;
    reg        lock_set;
    reg        debug_enable;
    reg        privileged;
    reg        glitch_detect;
    wire [7:0] data_out;

    // DUT
    secure_test dut (
        .clk(clk),
        .resetn(resetn),
        .write_en(write_en),
        .data_in(data_in),
        .lock_set(lock_set),
        .debug_enable(debug_enable),
        .privileged(privileged),
        .glitch_detect(glitch_detect),
        .data_out(data_out)
    );

    // Clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    initial begin
        // Init
        resetn       = 0;
        write_en     = 0;
        data_in      = 8'h00;
        lock_set     = 0;
        debug_enable = 0;
        privileged   = 0;
        glitch_detect= 0;

        // Reset (CWE-226 scrub)
        #12; resetn = 1; #10;

        // ------------------------------------------------------------
        // 1) CWE-1262 / 1234: lock + debug cannot override
        // ------------------------------------------------------------

        // Privileged writes secret before lock
        privileged = 1;
        write_en   = 1;
        data_in    = 8'hAA;
        #10; write_en = 0; #10;

        // Lock the register
        lock_set = 1;
        #10; lock_set = 0; #10;

        // Attempt normal write while locked (privileged)
        write_en = 1;
        data_in  = 8'h55;
        #10; write_en = 0; #10;

        $display("Locked normal write, data_out = 0x%0h (expect 0xAA)", data_out);

        // Enable debug while locked: should NOT override lock
        debug_enable = 1;
        write_en     = 1;
        data_in      = 8'h33;
        #10; write_en = 0; #10;

        $display("With debug_enable=1 while locked, data_out = 0x%0h (expect still 0xAA)", data_out);

        debug_enable = 0;

        // ------------------------------------------------------------
        // 2) CWE-1262 / 1256: unprivileged cannot write
        // ------------------------------------------------------------

        privileged = 0;  // unprivileged
        write_en   = 1;
        data_in    = 8'hF0;
        #10; write_en = 0; #10;

        $display("Unprivileged write attempt, data_out = 0x%0h (should remain 0xAA)", data_out);

        // ------------------------------------------------------------
        // 3) CWE-1247: glitch_detect forces safe state
        // ------------------------------------------------------------

        privileged = 1;
        write_en   = 1;
        data_in    = 8'hC3;
        #10; write_en = 0; #10;

        $display("Before glitch, data_out = 0x%0h", data_out);

        $display("Asserting glitch_detect...");
        glitch_detect = 1;
        #10;
        glitch_detect = 0;
        #10;

        $display("After glitch_detect, locked=%b, data_out=0x%0h (expect locked=1, data_out=0)", dut.locked, data_out);

        // ------------------------------------------------------------
        // 4) CWE-226: scrub on reset / reuse
        // ------------------------------------------------------------

        // Write new secret
        write_en = 1;
        data_in  = 8'h5A;
        #10; write_en = 0; #10;
        $display("Secret written, data_out = 0x%0h", data_out);

        // Reset scrub
        resetn = 0; #10; resetn = 1; #10;
        $display("After reset, data_out = 0x%0h (expect 0x00)", data_out);

        $finish;
    end
endmodule
