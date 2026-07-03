`timescale 1ns/1ps
`include "fixed.v"
module tb_test_secure;

    reg         clk;
    reg         reset;
    reg         glitch_detect;
    reg  [31:0] write_data;
    reg         req;
    reg  [1:0]  priv_lvl;
    wire [31:0] read_data;
    wire        fault;

    test_secure dut (
        .clk(clk),
        .reset(reset),
        .glitch_detect(glitch_detect),
        .write_data(write_data),
        .req(req),
        .priv_lvl(priv_lvl),
        .read_data(read_data),
        .fault(fault)
    );

    always #5 clk = ~clk;

    task step; begin #10; end endtask

    initial begin
        $display("=== Hardened Module CWE Testbench ===");

        clk = 0;
        reset = 1;
        glitch_detect = 0;
        req = 0;
        write_data = 32'h0;
        priv_lvl = 2'd0;
        step;

        // -------------------------------
        // CWE-226: reset scrubbing of secret key
        // -------------------------------
        $display("\n[CWE-226] Testing reset scrubbing...");
        reset = 0; step;

        // privileged write to secret key
        req = 1;
        priv_lvl = 2'd3;
        write_data = 32'hDEADBEEF;
        step;

        // assert reset, expect scrubbed key
        reset = 1; step;
        if (dut.REG_SKEY == 32'h0)
            $display("PASS: REG_SKEY scrubbed on reset.");
        else
            $display("FAIL: REG_SKEY not scrubbed on reset.");

        reset = 0; step;

        // -------------------------------
        // CWE-1262 / CWE-1256: access control on secret key
        // -------------------------------
        $display("\n[CWE-1262/1256] Testing access control...");
        req = 1;
        priv_lvl = 2'd0;          // unprivileged
        write_data = 32'hCAFEBABE;
        step;

        if (dut.REG_SKEY != 32'hCAFEBABE)
            $display("PASS: Unprivileged write did not modify secret key.");
        else
            $display("FAIL: Unprivileged write modified secret key.");

        if (read_data == 32'h0)
            $display("PASS: Secret key not readable (write-only, masked).");
        else
            $display("FAIL: Secret key leaked via read_data.");

        // -------------------------------
        // CWE-1247: glitch protection
        // -------------------------------
        $display("\n[CWE-1247] Testing glitch protection...");
        glitch_detect = 1; step;  // trigger glitch-safe state

        if (fault && dut.REG_SKEY == 32'h0 && dut.REG_CONF == 32'h0)
            $display("PASS: Glitch forces safe error state and scrubs sensitive registers.");
        else
            $display("FAIL: Glitch did not force safe state or scrub registers.");

        glitch_detect = 0; step;

        $display("\n=== Hardened Module CWE Testbench Complete ===");
        $finish;
    end

endmodule
