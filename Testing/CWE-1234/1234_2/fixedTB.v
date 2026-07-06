`timescale 1ns/1ps
`include "fixed.v"
module tb_secure;

    reg clk;
    reg rst_n;
    reg debug_mode;
    reg lock_config;
    reg write_enable;
    reg secure_access;
    reg glitch_detect;
    reg [7:0] addr;
    reg [31:0] data_in;
    wire [31:0] data_out;

    // DUT
    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .debug_mode(debug_mode),
        .lock_config(lock_config),
        .write_enable(write_enable),
        .secure_access(secure_access),
        .glitch_detect(glitch_detect),
        .addr(addr),
        .data_in(data_in),
        .data_out(data_out)
    );

    always #5 clk = ~clk;

    task write_reg(input priv, input [7:0] a, input [31:0] d);
    begin
        secure_access = priv;
        addr          = a;
        data_in       = d;
        write_enable  = 1;
        #10;
        write_enable  = 0;
        #10;
    end
    endtask

    initial begin
        $display("=== Secure Module Testbench ===");

        clk          = 0;
        rst_n        = 0;
        debug_mode   = 0;
        lock_config  = 0;
        write_enable = 0;
        secure_access= 0;
        glitch_detect= 0;
        addr         = 0;
        data_in      = 0;

        // Reset and scrubbing (CWE-226)
        #20 rst_n = 1; #20;
        $display("\n[CWE-226] After reset, config_regs and mpu_config should be 0");
        addr = 8'h20; #10; $display("config_regs[0x20] = %h", data_out);
        addr = 8'h10; #10; $display("mpu_config = %h", data_out);

        // Privileged write (trusted) (CWE-1189/1262/1256)
        $display("\n[Privileged] Writing MPU config and config_regs...");
        write_reg(1'b1, 8'h10, 32'hCAFEBABE);
        write_reg(1'b1, 8'h20, 32'hDEADBEEF);

        addr = 8'h10; #10; $display("mpu_config (privileged read) = %h", data_out);
        addr = 8'h20; #10; $display("config_regs[0x20] (privileged read) = %h", data_out);

        // Unprivileged access should be blocked (CWE-1189/1256/1262)
        $display("\n[Unprivileged] Attempting to read/write sensitive registers...");
        write_reg(1'b0, 8'h10, 32'h12345678); // should NOT change mpu_config
        addr = 8'h10; #10; $display("mpu_config (unprivileged read) = %h (should be 0)", data_out);

        write_reg(1'b0, 8'hFF, 32'h1); // cannot lock
        addr = 8'hFF; #10; $display("config_locked (unprivileged read) = %h (should be 0)", data_out);

        // Locking via privileged lock_config (CWE-1234/1262)
        $display("\n[Lock] Privileged lock_config sets one-way lock...");
        secure_access = 1;
        lock_config   = 1;
        #10 lock_config = 0; #10;

        addr = 8'hFF; #10; $display("config_locked (privileged read) = %h (should be 1)", data_out);

        $display("[Lock] Attempting privileged write after lock (should be blocked)...");
        write_reg(1'b1, 8'h10, 32'hAAAAAAAA);
        addr = 8'h10; #10; $display("mpu_config after locked write = %h (should remain CAFEBABE)", data_out);

        // Debug mode should NOT override lock, and clears sensitive state (CWE-1191/1234)
        $display("\n[Debug] Entering debug mode...");
        debug_mode = 1; #20;
        addr = 8'h10; #10; $display("mpu_config in debug (privileged read) = %h (should be 0)", data_out);

        $display("[Debug] Attempting write in debug (should be blocked)...");
        write_reg(1'b1, 8'h10, 32'hBBBBBBBB);
        addr = 8'h10; #10; $display("mpu_config after debug write = %h (should still be 0)", data_out);
        debug_mode = 0; #20;

        // Glitch detection forces safe state (CWE-1247)
        $display("\n[Glitch] Asserting glitch_detect...");
        glitch_detect = 1; #20;
        addr = 8'h10; #10; $display("mpu_config under glitch = %h (should be 0)", data_out);
        addr = 8'hFF; #10; $display("config_locked under glitch = %h (should be 1)", data_out);

        $display("[Glitch] Attempting write under glitch (should be blocked)...");
        write_reg(1'b1, 8'h10, 32'hFACEFACE);
        addr = 8'h10; #10; $display("mpu_config after glitch write = %h (should still be 0)", data_out);
        glitch_detect = 0; #20;

        $display("\n=== Secure Module Tests Complete ===");
        $finish;
    end

endmodule
