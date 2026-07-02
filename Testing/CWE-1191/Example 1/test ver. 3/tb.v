`timescale 1ns/1ps

`include "fixed1.v"
module Example1_tb;

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
    Example1 dut (
        .clk            (clk),
        .rst_n          (rst_n),
        .dbg_en         (dbg_en),
        .dbg_wr         (dbg_wr),
        .dbg_addr       (dbg_addr),
        .dbg_wdata      (dbg_wdata),
        .dbg_rdata      (dbg_rdata),
        .privilege_level(privilege_level),
        .secret_key     (secret_key)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Task: simple debug write
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

    // Task: simple debug read
    task dbg_read(input [3:0] addr);
    begin
        @(negedge clk);
        dbg_en   <= 1'b1;
        dbg_wr   <= 1'b0;
        dbg_addr <= addr;
        @(negedge clk);
        $display("DBG READ addr=%0h data=%08h time=%0t", addr, dbg_rdata, $time);
        dbg_en   <= 1'b0;
        dbg_addr <= 4'h0;
    end
    endtask

    initial begin
        // Default values
        dbg_en   = 0;
        dbg_wr   = 0;
        dbg_addr = 0;
        dbg_wdata= 0;

        // --------------------------------------------------------------------
        // RESET SEQUENCE – CWE-226: check that secret_key is NOT scrubbed
        // --------------------------------------------------------------------
        rst_n = 0;
        repeat(2) @(negedge clk);
        rst_n = 1;
        repeat(2) @(negedge clk);

        $display("After reset: secret_key=%08h privilege_level=%0d", secret_key, privilege_level);

        // CWE-226: secret_key should be zeroed; here it is DEADBEEF (vulnerability)
        if (secret_key !== 32'hDEADBEEF) begin
            $display("CWE-226 TEST: expected DEADBEEF per vulnerable design, got %08h", secret_key);
        end else begin
            $display("CWE-226 TEST: secret_key not scrubbed on reset (vulnerability present).");
        end

        // --------------------------------------------------------------------
        // CWE-1191 / CWE-1262 / CWE-1256:
        // Use debug interface with no authentication or privilege gating
        // --------------------------------------------------------------------

        // 1) Read secret_key via debug – should be blocked in secure design
        dbg_read(4'h0); // exposes secret_key_reg directly

        // 2) Write a new secret key via debug – untrusted source controls key
        dbg_write(4'h0, 32'hCAFEBABE);
        repeat(2) @(negedge clk);
        $display("After dbg_write: secret_key=%08h", secret_key);

        // CWE-1262: secret_key is writable via debug without access control
        if (secret_key === 32'hCAFEBABE)
            $display("CWE-1262 TEST: secret_key writable from debug (vulnerability present).");

        // 3) Elevate privilege via debug – CWE-1256 / CWE-1262
        dbg_write(4'h1, 32'h00000003); // set privilege_reg[1:0] = 3 (root)
        repeat(2) @(negedge clk);
        $display("After dbg_write privilege: privilege_level=%0d", privilege_level);

        if (privilege_level == 2'b11)
            $display("CWE-1256/1262 TEST: privilege_level changed via debug (vulnerability present).");

        // 4) Read back privilege via debug – should be masked in secure design
        dbg_read(4'h1);

        // --------------------------------------------------------------------
        // CWE-1234: debug mode overrides any hypothetical locks
        // Here, dbg_en alone enables full access; no lock bits exist.
        // --------------------------------------------------------------------
        @(negedge clk);
        dbg_en   <= 1'b1;
        dbg_wr   <= 1'b1;
        dbg_addr <= 4'h0;
        dbg_wdata<= 32'hAAAAAAAA;
        @(negedge clk);
        dbg_en   <= 1'b0;
        dbg_wr   <= 1'b0;
        dbg_addr <= 4'h0;
        dbg_wdata<= 32'h0;
        repeat(2) @(negedge clk);

        $display("CWE-1234 TEST: secret_key after debug override=%08h", secret_key);
        $display("Debug enable alone allows overriding key (lock-bypass vulnerability).");

        // --------------------------------------------------------------------
        // CWE-226: reuse after reset – key still non-zero and readable
        // --------------------------------------------------------------------
        rst_n = 0;
        repeat(2) @(negedge clk);
        rst_n = 1;
        repeat(2) @(negedge clk);

        $display("After second reset: secret_key=%08h", secret_key);
        dbg_read(4'h0); // still readable, not scrubbed

        $display("CWE-226 TEST: resource reused after reset without zeroization (vulnerability persists).");

        // Finish
        $display("Testbench completed – vulnerabilities exercised.");
        #20;
        $finish;
    end

endmodule
