`timescale 1ns/1ps
`include "fixed.v"
module tb_test_secure;

    reg         clk;
    reg         rst_n;
    reg         wr_req;
    reg  [15:0] din;
    reg         lock_flag;
    reg         scan_mode;
    reg         priv_wr;
    reg         glitch_detect;
    wire [15:0] dout;

    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .wr_req(wr_req),
        .din(din),
        .lock_flag(lock_flag),
        .scan_mode(scan_mode),
        .priv_wr(priv_wr),
        .glitch_detect(glitch_detect),
        .dout(dout)
    );

    always #5 clk = ~clk;

    task show;
        $display("[%0t] rst=%b lock_flag=%b lock_status=%b state=%0d wr=%b priv=%b scan=%b glitch=%b din=%h dout=%h",
                 $time, rst_n, lock_flag, dut.lock_status, dut.sec_state,
                 wr_req, priv_wr, scan_mode, glitch_detect, din, dout);
    endtask

    initial begin
        clk = 0;
        rst_n = 0;
        wr_req = 0;
        din = 16'h0000;
        lock_flag = 0;
        scan_mode = 0;
        priv_wr = 0;
        glitch_detect = 0;

        // Power-on reset
        #10 rst_n = 1; show;

        // CWE-1262 / 1256: unprivileged write must be denied
        $display("\n=== Unprivileged write (should be blocked) ===");
        #10 wr_req = 1; priv_wr = 0; din = 16'hBEEF; show;
        #10 show;

        // CWE-1262 / 1256: privileged write allowed when unlocked
        $display("\n=== Privileged write when unlocked (should succeed) ===");
        #10 priv_wr = 1; din = 16'hCAFE; show;
        #10 show;

        // Lock the register (one-way fuse)
        $display("\n=== Lock fuse set (writes must be denied) ===");
        #10 lock_flag = 1; wr_req = 0; show;
        #10 show;

        // Attempt privileged write while locked (must be blocked)
        #10 wr_req = 1; din = 16'hDEAD; show;
        #10 show;

        // CWE-1234: scan_mode must NOT override lock
        $display("\n=== Debug/scan mode must not bypass lock ===");
        #10 scan_mode = 1; wr_req = 1; din = 16'hC0DE; show;
        #10 show;

        // CWE-226: scrubbing on lock and debug entry
        $display("\n=== Scrubbing behavior ===");
        // Reset and write sensitive value
        #10 rst_n = 0;
        #10 rst_n = 1; priv_wr = 1; wr_req = 1; lock_flag = 0; scan_mode = 0; din = 16'hFACE; show;
        #10 show;
        // Lock: should scrub
        #10 lock_flag = 1; wr_req = 0; show;
        #10 show;
        // Reset: should scrub
        #10 rst_n = 0; show;
        #10 rst_n = 1; show;

        // CWE-1247: glitch forces error state and safe values
        $display("\n=== Glitch detection forces safe state ===");
        #10 priv_wr = 1; wr_req = 1; din = 16'h1234; show;
        #10 show;
        #10 glitch_detect = 1; show;
        #10 show;
        // After glitch, writes must be blocked and dout kept safe
        #10 glitch_detect = 0; wr_req = 1; din = 16'hFFFF; show;
        #10 show;

        $display("\n=== SECURE TEST COMPLETE ===");
        #20 $finish;
    end

endmodule
