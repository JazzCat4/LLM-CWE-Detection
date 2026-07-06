`timescale 1ns/1ps
`include "1262_1.v"
module tb_test_vuln;

    reg         clk;
    reg         reset;
    reg  [31:0] write_data;
    reg         req;
    reg  [1:0]  priv_lvl;
    wire [31:0] read_data;

    // DUT
    test dut (
        .clk(clk),
        .reset(reset),
        .write_data(write_data),
        .req(req),
        .priv_lvl(priv_lvl),
        .read_data(read_data)
    );

    // Clock
    always #5 clk = ~clk;

    // Helper task
    task step;
        begin
            #10;
        end
    endtask

    initial begin
        $display("=== Starting Vulnerability Testbench ===");

        clk = 0;
        reset = 1;
        req = 0;
        write_data = 32'h0;
        priv_lvl = 2'd0;

        step;

        // -------------------------------
        // CWE‑226: Sensitive data not cleared on reset
        // -------------------------------
        $display("\n[CWE‑226] Testing reset scrubbing...");
        reset = 0; step;  // allow initial writes
        req = 1;
        write_data = 32'hDEADBEEF;
        step;

        reset = 1; step;  // assert reset
        if (dut.REG_SKEY !== 32'h0 && dut.REG_SKEY !== 32'hA55C)
            $display("FAIL: REG_SKEY retains sensitive data across reset.");
        else
            $display("FAIL (expected): REG_SKEY not scrubbed on reset.");

        // -------------------------------
        // CWE‑1262: Missing privilege checks on sensitive registers
        // -------------------------------
        $display("\n[CWE‑1262] Testing access control...");
        reset = 0; step;

        req = 1;
        priv_lvl = 2'd0;       // unprivileged
        write_data = 32'hCAFEBABE;
        step;

        if (dut.REG_SKEY == 32'hCAFEBABE)
            $display("FAIL: Unprivileged write modified secret key (REG_SKEY).");
        else
            $display("FAIL (expected): REG_SKEY write allowed without privilege.");

        // Read path test
        if (read_data == dut.REG_SKEY)
            $display("FAIL: Unprivileged read exposed secret key.");
        else
            $display("FAIL (expected): Secret key readable without privilege.");

        // -------------------------------
        // CWE‑1256: Unprivileged access to hardware‑sensitive features
        // -------------------------------
        $display("\n[CWE‑1256] Testing software access to hardware‑sensitive features...");
        req = 1;
        priv_lvl = 2'd0;
        write_data = 32'h12345678;
        step;

        if (dut.REG_SKEY == 32'h12345678)
            $display("FAIL: Unprivileged software can modify hardware‑sensitive secret key.");
        else
            $display("FAIL (expected): Secret key not privilege‑gated.");

        // -------------------------------
        // CWE‑1247: Glitch vulnerability test
        // -------------------------------
        $display("\n[CWE‑1247] Testing glitch susceptibility...");
        reset = 0;
        req = 1;
        priv_lvl = 2'd0;
        write_data = 32'hFACEFACE;

        // Inject a clock glitch (double toggle)
        #1 clk = ~clk;
        #1 clk = ~clk;
        step;

        if (dut.REG_SKEY == 32'hFACEFACE)
            $display("FAIL: Clock glitch caused unauthorized write to REG_SKEY.");
        else
            $display("FAIL (expected): No glitch protection; write occurred or could occur.");

        $display("\n=== Vulnerability Testbench Complete ===");
        $finish;
    end

endmodule
