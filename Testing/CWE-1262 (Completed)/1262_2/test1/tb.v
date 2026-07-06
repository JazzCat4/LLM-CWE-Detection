`timescale 1ns/1ps
`include "1262_2.v"
module tb_test_vuln;

    reg clk;
    reg rstn;
    reg [11:0] addr;
    reg [31:0] wdata;
    reg wr_en;
    reg [1:0] priv_mode;
    wire [31:0] rdata;

    // Instantiate DUT
    test dut (
        .clk(clk),
        .rstn(rstn),
        .addr(addr),
        .wdata(wdata),
        .wr_en(wr_en),
        .priv_mode(priv_mode),
        .rdata(rdata)
    );

    // Clock generation
    always #5 clk = ~clk;

    initial begin
        $display("=== Starting Vulnerability Testbench ===");

        clk = 0;
        rstn = 0;
        addr = 0;
        wdata = 0;
        wr_en = 0;
        priv_mode = 2'b00; // unprivileged

        // -------------------------------
        // CWE-226: Sensitive data not cleared before reuse
        // -------------------------------
        $display("\n[CWE-226] Testing sensitive register reuse without scrubbing");

        #10 rstn = 1;

        // Write secret key
        addr = 12'h8FF;
        wdata = 32'hDEADBEEF;
        wr_en = 1;
        #10 wr_en = 0;

        // Read back key (should NOT be allowed)
        #10 addr = 12'h8FF;
        #10 $display("Read key_reg = %h (leak!)", rdata);

        // Overwrite key without scrubbing
        addr = 12'h8FF;
        wdata = 32'hCAFEBABE;
        wr_en = 1;
        #10 wr_en = 0;

        // Read overwritten key
        #10 addr = 12'h8FF;
        #10 $display("Read overwritten key_reg = %h (no scrubbing!)", rdata);

        // -------------------------------
        // CWE-1262: No privilege enforcement
        // -------------------------------
        $display("\n[CWE-1262] Testing missing privilege checks");

        priv_mode = 2'b00; // unprivileged
        addr = 12'h300;
        wdata = 32'h12345678;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h300;
        #10 $display("Unprivileged read of cntrl_reg = %h (should fault!)", rdata);

        addr = 12'h8FF;
        #10 $display("Unprivileged read of key_reg = %h (critical leak!)", rdata);

        // -------------------------------
        // CWE-1256: Software-accessible hardware features
        // -------------------------------
        $display("\n[CWE-1256] Testing unrestricted software access");

        priv_mode = 2'b00; // unprivileged
        addr = 12'h300;
        wdata = 32'hA5A5A5A5;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h300;
        #10 $display("Unprivileged write/read of cntrl_reg = %h (should be blocked!)", rdata);

        // -------------------------------
        // CWE-1247: Clock glitch simulation
        // -------------------------------
        $display("\n[CWE-1247] Testing glitch susceptibility");

        // Write a known value
        addr = 12'h8FF;
        wdata = 32'hFACEFACE;
        wr_en = 1;
        #10 wr_en = 0;

        // Inject a clock glitch (double toggle)
        #2 clk = ~clk;
        #2 clk = ~clk;

        // Read key after glitch
        #10 addr = 12'h8FF;
        #10 $display("Read key_reg after clock glitch = %h (should be protected!)", rdata);

        // Glitch reset
        #2 rstn = 0;
        #2 rstn = 1;

        // Read after glitch reset
        #10 addr = 12'h8FF;
        #10 $display("Read key_reg after glitch reset = %h (should be safe-cleared!)", rdata);

        $display("\n=== Vulnerability Testbench Complete ===");
        $finish;
    end

endmodule
