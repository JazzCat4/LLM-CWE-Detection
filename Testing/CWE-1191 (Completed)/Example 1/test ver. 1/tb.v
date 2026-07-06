// Testbench targeting CWE-1191, CWE-1234, CWE-1256 for jtag_debug_ctrl_buggy

`timescale 1ns/1ps
`include "Example1.v"

module tb_jtag_debug_ctrl_buggy;

    // DUT ports
    reg         clk;
    reg         rst_n;
    reg         dbg_en;
    reg         dbg_wr;
    reg  [3:0]  dbg_addr;
    reg  [31:0] dbg_wdata;
    wire [31:0] dbg_rdata;
    wire [1:0]  privilege_level;
    wire [31:0] secret_key;

    // Instantiate DUT
    Ex1 dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .dbg_en          (dbg_en),
        .dbg_wr          (dbg_wr),
        .dbg_addr        (dbg_addr),
        .dbg_wdata       (dbg_wdata),
        .dbg_rdata       (dbg_rdata),
        .privilege_level (privilege_level),
        .secret_key      (secret_key)
    );

    // Simple clock
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Tasks for debug read/write
    task dbg_write(input [3:0] addr, input [31:0] data);
    begin
        @(negedge clk);
        dbg_en   <= 1'b1;
        dbg_wr   <= 1'b1;
        dbg_addr <= addr;
        dbg_wdata<= data;
        @(negedge clk);
        dbg_en   <= 1'b0;
        dbg_wr   <= 1'b0;
        dbg_addr <= 4'h0;
        dbg_wdata<= 32'h0;
    end
    endtask

    task dbg_read(input [3:0] addr);
    begin
        @(negedge clk);
        dbg_en   <= 1'b1;
        dbg_wr   <= 1'b0;
        dbg_addr <= addr;
        @(negedge clk);
        $display("DBG READ addr=%0h data=%08h", addr, dbg_rdata);
        dbg_en   <= 1'b0;
        dbg_addr <= 4'h0;
    end
    endtask

    // Main stimulus
    initial begin
        // Init
        dbg_en   = 0;
        dbg_wr   = 0;
        dbg_addr = 0;
        dbg_wdata= 0;

        // Reset
        rst_n = 0;
        repeat (2) @(negedge clk);
        rst_n = 1;
        repeat (2) @(negedge clk);

        // ------------------------------------------------------------
        // CWE-1191: Attempt debug access with no authentication / gating
        // ------------------------------------------------------------
        $display("\n[CWE-1191] Unauthenticated debug access to secret_key and privilege_level");
        // Read secret key directly via debug
        dbg_read(4'h0);
        // Read privilege level directly via debug
        dbg_read(4'h1);

        // ------------------------------------------------------------
        // CWE-1256: Use debug interface as software-like CSR to manipulate privileged features
        // ------------------------------------------------------------
        $display("\n[CWE-1256] Arbitrary write to privilege_level and secret_key via debug interface");
        // Elevate privilege to root (3)
        dbg_write(4'h1, 32'h0000_0003);
        @(negedge clk);
        $display("Privilege_level after debug write = %0d", privilege_level);

        // Overwrite secret key via debug
        dbg_write(4'h0, 32'hCAFEBABE);
        @(negedge clk);
        $display("Secret_key after debug write = %08h", secret_key);

        // ------------------------------------------------------------
        // CWE-1234: Show that any hypothetical lock/reset can be overridden by debug/reset
        // (Here we simulate a 'locked' state by setting privilege to user, then overriding)
        // ------------------------------------------------------------
        $display("\n[CWE-1234] Override of lock-like behavior via debug and reset");
        // Simulate 'lock' by setting privilege to user (0)
        dbg_write(4'h1, 32'h0000_0000);
        @(negedge clk);
        $display("Privilege_level locked to user = %0d", privilege_level);

        // Now override 'lock' via debug write to root again
        dbg_write(4'h1, 32'h0000_0003);
        @(negedge clk);
        $display("Privilege_level after override via debug = %0d", privilege_level);

        // Toggle reset to reinitialize secret_key to known constant
        rst_n = 0;
        @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        $display("Secret_key after external reset = %08h", secret_key);

        $display("\n[TESTBENCH DONE]");
        #20;
        $finish;
    end

endmodule
