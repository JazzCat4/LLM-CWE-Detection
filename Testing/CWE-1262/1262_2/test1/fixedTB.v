`timescale 1ns/1ps
`include "fixed.v"
module tb_test_secure;

    reg clk;
    reg rstn;
    reg glitch_detect;
    reg [11:0] addr;
    reg [31:0] wdata;
    reg wr_en;
    reg [1:0] priv_mode;
    wire [31:0] rdata;

    // Instantiate DUT
    test_secure dut (
        .clk(clk),
        .rstn(rstn),
        .glitch_detect(glitch_detect),
        .addr(addr),
        .wdata(wdata),
        .wr_en(wr_en),
        .priv_mode(priv_mode),
        .rdata(rdata)
    );

    // Clock generation
    always #5 clk = ~clk;

    initial begin
        $display("=== Starting Secure Module Validation Testbench ===");

        clk = 0;
        rstn = 0;
        glitch_detect = 0;
        addr = 0;
        wdata = 0;
        wr_en = 0;
        priv_mode = 2'b00; // start unprivileged

        // -------------------------------
        // CWE-226: Sensitive register reuse & scrubbing
        // -------------------------------
        $display("\n[CWE-226] Testing sensitive register scrubbing enforcement");

        #10 rstn = 1;

        // Attempt to write key while unprivileged (should fail)
        addr = 12'h8FF;
        wdata = 32'hDEADBEEF;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h8FF;
        #10 $display("Unprivileged read key_reg = %h (should be 0)", rdata);

        // Privileged write
        priv_mode = 2'b11;
        addr = 12'h8FF;
        wdata = 32'hCAFEBABE;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h8FF;
        #10 $display("Privileged read key_reg = %h (should be CAFEBABE)", rdata);

        // Attempt overwrite without scrub (should be blocked)
        addr = 12'h8FF;
        wdata = 32'hFACEFACE;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h8FF;
        #10 $display("Overwrite without scrub key_reg = %h (should still be CAFEBABE)", rdata);

        // Issue scrub command via cntrl_reg[0]
        addr = 12'h300;
        wdata = 32'h00000001; // scrub bit
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h8FF;
        #10 $display("After scrub key_reg = %h (should be 0)", rdata);

        // Now write new key (allowed)
        addr = 12'h8FF;
        wdata = 32'h12345678;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h8FF;
        #10 $display("After scrub+write key_reg = %h (should be 12345678)", rdata);

        // -------------------------------
        // CWE-1262: Privilege enforcement
        // -------------------------------
        $display("\n[CWE-1262] Testing privilege gating");

        priv_mode = 2'b00; // drop privilege

        addr = 12'h300;
        #10 $display("Unprivileged read cntrl_reg = %h (should be 0)", rdata);

        addr = 12'h8FF;
        #10 $display("Unprivileged read key_reg = %h (should be 0)", rdata);

        // -------------------------------
        // CWE-1256: Restriction of hardware features
        // -------------------------------
        $display("\n[CWE-1256] Testing restricted access to control register");

        addr = 12'h300;
        wdata = 32'hA5A5A5A5;
        wr_en = 1;
        #10 wr_en = 0;

        #10 addr = 12'h300;
        #10 $display("Unprivileged write/read cntrl_reg = %h (should be 0)", rdata);

        // -------------------------------
        // CWE-1247: Glitch protection
        // -------------------------------
        $display("\n[CWE-1247] Testing glitch detection safe-state behavior");

        priv_mode = 2'b11;

        // Write a known key
        addr = 12'h8FF;
        wdata = 32'hFACEFACE;
        wr_en = 1;
        #10 wr_en = 0;

        // Trigger glitch
        #5 glitch_detect = 1;
        #10 glitch_detect = 0;

        // Read key after glitch (should be cleared)
        addr = 12'h8FF;
        #10 $display("Read key_reg after glitch = %h (should be 0)", rdata);

        // Error state blocks further access
        addr = 12'h300;
        #10 $display("Read cntrl_reg after glitch = %h (should be 0)", rdata);

        $display("\n=== Secure Module Validation Complete ===");
        $finish;
    end

endmodule
