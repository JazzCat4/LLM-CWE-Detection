`timescale 1ns/1ps
`include "1234_2.v"
module tb_vuln;

    reg clk;
    reg rst_n;
    reg debug_mode;
    reg lock_config;     // unused in DUT
    reg write_enable;
    reg [7:0] addr;
    reg [31:0] data_in;
    wire [31:0] data_out;

    // Instantiate DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .debug_mode(debug_mode),
        .lock_config(lock_config),
        .write_enable(write_enable),
        .addr(addr),
        .data_in(data_in),
        .data_out(data_out)
    );

    // Clock generation
    always #5 clk = ~clk;

    task write_reg(input [7:0] a, input [31:0] d);
    begin
        addr = a;
        data_in = d;
        write_enable = 1;
        #10;
        write_enable = 0;
        #10;
    end
    endtask

    initial begin
        $display("=== Vulnerability Validation Testbench ===");

        clk = 0;
        rst_n = 0;
        debug_mode = 0;
        lock_config = 0;
        write_enable = 0;
        addr = 0;
        data_in = 0;

        // -------------------------------
        // CWE-226: Sensitive data persists across reset
        // -------------------------------
        $display("\n[CWE-226] Writing sensitive data...");
        write_reg(8'h20, 32'hDEADBEEF);   // sensitive config
        write_reg(8'h10, 32'hCAFEBABE);   // MPU config

        $display("[CWE-226] Asserting reset...");
        rst_n = 0;
        #20;
        rst_n = 1;
        #20;

        $display("[CWE-226] Reading back registers after reset...");
        addr = 8'h20; #10;
        $display("config_regs[0x20] = %h (should have been scrubbed!)", data_out);

        addr = 8'h10; #10;
        $display("mpu_config = %h (reset cleared, but config_regs did NOT)", data_out);

        // -------------------------------
        // CWE-1189: Untrusted agent writes privileged registers
        // -------------------------------
        $display("\n[CWE-1189] Untrusted agent writing MPU config...");
        write_reg(8'h10, 32'h12345678);
        addr = 8'h10; #10;
        $display("mpu_config = %h (untrusted write succeeded!)", data_out);

        // -------------------------------
        // CWE-1262: No access control on sensitive registers
        // -------------------------------
        $display("\n[CWE-1262] Reading sensitive lock bit without privilege...");
        addr = 8'hFF; #10;
        $display("config_locked = %h (read allowed!)", data_out);

        // -------------------------------
        // CWE-1256: Unprivileged writes to privileged features
        // -------------------------------
        $display("\n[CWE-1256] Unprivileged write to lock bit...");
        write_reg(8'hFF, 32'h1);   // lock system
        addr = 8'hFF; #10;
        $display("config_locked = %h (lock set)", data_out);

        // -------------------------------
        // CWE-1234 & CWE-1191: Debug overrides lock
        // -------------------------------
        $display("\n[CWE-1234/CWE-1191] Debug mode overriding lock...");
        debug_mode = 1;
        write_reg(8'h10, 32'hAAAAAAAA);   // should be blocked but is allowed
        addr = 8'h10; #10;
        $display("mpu_config = %h (debug bypassed lock!)", data_out);

        // -------------------------------
        // CWE-1260: Unsafe MPU region definitions accepted
        // -------------------------------
        $display("\n[CWE-1260] Writing overlapping MPU region definitions...");
        write_reg(8'h10, 32'h0000FFFF);   // region A
        write_reg(8'h10, 32'h00007FFF);   // overlapping region B
        addr = 8'h10; #10;
        $display("mpu_config = %h (overlap accepted without validation!)", data_out);

        // -------------------------------
        // CWE-1247: Clock glitch bypassing lock
        // -------------------------------
        $display("\n[CWE-1247] Simulating clock glitch...");
        debug_mode = 0;
        write_reg(8'hFF, 32'h1); // lock system

        // glitch: double pulse
        #1 clk = 1; #1 clk = 0; #1 clk = 1;

        write_reg(8'h10, 32'hFACEFACE); // should be blocked
        addr = 8'h10; #10;
        $display("mpu_config = %h (glitch allowed write!)", data_out);

        $display("\n=== Vulnerability Tests Complete ===");
        $finish;
    end

endmodule
