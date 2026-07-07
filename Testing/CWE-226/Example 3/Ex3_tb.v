`timescale 1ns/1ps

module tb_test_vuln;

    reg clk;
    reg rst;
    reg write_en;
    reg read_en;
    reg [1:0] addr;
    reg [127:0] secret_key_in;
    wire [127:0] secret_key_out;

    // DUT
    test dut (
        .clk(clk),
        .rst(rst),
        .write_en(write_en),
        .read_en(read_en),
        .addr(addr),
        .secret_key_in(secret_key_in),
        .secret_key_out(secret_key_out)
    );

    // Clock
    always #5 clk = ~clk;

    initial begin
        clk = 0;
        rst = 0;
        write_en = 0;
        read_en = 0;
        addr = 0;
        secret_key_in = 0;

        $display("\n=== CWE Vulnerability Validation Testbench ===\n");

        // ------------------------------------------------------------
        // CWE-226: Sensitive Information Not Removed Before Reuse
        // ------------------------------------------------------------
        $display("CWE-226 TEST: Keys persist across reset (should NOT happen)");

        addr = 2'b01;
        secret_key_in = 128'hDEADBEEF_DEADBEEF_DEADBEEF_DEADBEEF;
        write_en = 1;
        #10 write_en = 0;

        rst = 1; #10 rst = 0; // Reset only clears secret_key_out

        read_en = 1; #10 read_en = 0;

        $display("After reset, secret_key_out = %h (should be 0, but key persists!)",
                 secret_key_out);

        // ------------------------------------------------------------
        // CWE-1189: Improper Isolation of Shared Resources
        // ------------------------------------------------------------
        $display("\nCWE-1189 TEST: Untrusted agent can read/write all key slots");

        addr = 2'b11;
        secret_key_in = 128'hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
        write_en = 1; #10 write_en = 0;

        read_en = 1; #10 read_en = 0;

        $display("Untrusted read of key slot 3 = %h (should be blocked!)",
                 secret_key_out);

        // ------------------------------------------------------------
        // CWE-1256: Improper Restriction of Software Interfaces
        // ------------------------------------------------------------
        $display("\nCWE-1256 TEST: Unprivileged writes allowed");

        addr = 2'b00;
        secret_key_in = 128'hBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;
        write_en = 1; #10 write_en = 0;

        read_en = 1; #10 read_en = 0;

        $display("Unprivileged write/read of key slot 0 = %h (should fault!)",
                 secret_key_out);

        // ------------------------------------------------------------
        // CWE-1262: Improper Access Control for Register Interface
        // ------------------------------------------------------------
        $display("\nCWE-1262 TEST: No read/write access control");

        addr = 2'b10;
        secret_key_in = 128'hCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC;
        write_en = 1; #10 write_en = 0;

        read_en = 1; #10 read_en = 0;

        $display("Read of sensitive key slot 2 = %h (should be masked!)",
                 secret_key_out);

        // ------------------------------------------------------------
        // CWE-1300: Side-channel leakage potential
        // ------------------------------------------------------------
        $display("\nCWE-1300 TEST: Key-dependent switching activity");

        addr = 2'b01;
        secret_key_in = 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        write_en = 1; #10 write_en = 0;

        read_en = 1; #10 read_en = 0;

        $display("Key-dependent output = %h (switching reveals key bits!)",
                 secret_key_out);

        $display("\n=== END OF TESTS ===\n");
        $finish;
    end

endmodule
