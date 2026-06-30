`timescale 1ns/1ps
`include "fixed.v"
module periph_regs_tb;

    // DUT inputs
    reg         clk;
    reg         rst_n;
    reg         reg_wen;
    reg         reg_ren;
    reg  [2:0]  reg_addr;
    reg  [31:0] reg_wdata;
    wire [31:0] reg_rdata;
    reg  [1:0]  cpu_privilege_level;
    reg         user_mode;

    // DUT outputs
    wire [31:0] crypto_key;
    wire [31:0] security_config;

    // Instantiate DUT
    periph_regs dut (
        .clk(clk),
        .rst_n(rst_n),
        .reg_wen(reg_wen),
        .reg_ren(reg_ren),
        .reg_addr(reg_addr),
        .reg_wdata(reg_wdata),
        .reg_rdata(reg_rdata),
        .cpu_privilege_level(cpu_privilege_level),
        .user_mode(user_mode),
        .crypto_key(crypto_key),
        .security_config(security_config)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Simple bus write/read helpers
    task write_reg(input [2:0] addr, input [31:0] data);
    begin
        @(negedge clk);
        reg_addr  <= addr;
        reg_wdata <= data;
        reg_wen   <= 1'b1;
        reg_ren   <= 1'b0;
        @(negedge clk);
        reg_wen   <= 1'b0;
    end
    endtask

    task read_reg(input [2:0] addr, output [31:0] data);
    begin
        @(negedge clk);
        reg_addr <= addr;
        reg_ren  <= 1'b1;
        reg_wen  <= 1'b0;
        @(negedge clk);
        data = reg_rdata;
        reg_ren <= 1'b0;
    end
    endtask

    // -------------------------
    // CWE-226: resource reuse / scrubbing
    // -------------------------
    task test_cwe226;
        reg [31:0] rd;
    begin
        $display("=== CWE-226 test: scrubbing on reuse/reset ===");

        // 1) Write known pattern to crypto_key and security_config
        write_reg(3'h1, 32'hCAFEBABE); // crypto_key_reg
        write_reg(3'h0, 32'h1234_5678); // security_config_reg

        // 2) "Release" resource: simulate new owner by reading back
        read_reg(3'h1, rd);
        $display("Before reset, crypto_key_reg = 0x%08x", rd);
        read_reg(3'h0, rd);
        $display("Before reset, security_config_reg = 0x%08x", rd);

        // 3) Assert reset: expect scrub/zero or non-sensitive values
        @(negedge clk);
        rst_n <= 1'b0;
        @(negedge clk);
        rst_n <= 1'b1;

        // 4) After reset, verify prior contents are not preserved
        read_reg(3'h1, rd);
        $display("After reset, crypto_key_reg = 0x%08x (should NOT be CAFEBABE)", rd);
        read_reg(3'h0, rd);
        $display("After reset, security_config_reg = 0x%08x (should NOT be 12345678)", rd);

        // 5) Optional: treat status_reg bit[0] as 'ciphertext valid' and expect scrub
        // Write ciphertext-valid flag
        write_reg(3'h2, 32'h0000_0001);
        // Expect implementation to scrub key/config when ciphertext becomes valid
        read_reg(3'h1, rd);
        $display("After ciphertext valid, crypto_key_reg = 0x%08x (should be scrubbed)", rd);
        read_reg(3'h0, rd);
        $display("After ciphertext valid, security_config_reg = 0x%08x (should be scrubbed)", rd);
    end
    endtask

    // -------------------------
    // CWE-1262: improper access control for register interface
    // -------------------------
    task test_cwe1262;
        reg [31:0] rd;
    begin
        $display("=== CWE-1262 test: unprivileged access to sensitive CSRs ===");

        // Set unprivileged mode
        cpu_privilege_level <= 2'b00; // lowest privilege
        user_mode           <= 1'b1;  // user mode

        // 1) Attempt to write all registers from unprivileged mode
        write_reg(3'h0, 32'hAAAA_BBBB); // security_config_reg (privileged)
        write_reg(3'h1, 32'hCCCC_DDDD); // crypto_key_reg (privileged)
        write_reg(3'h2, 32'hEEEE_FFFF); // status_reg (mixed)
        write_reg(3'h3, 32'h1111_2222); // version_reg (should be read-only)

        // 2) Read back all registers from unprivileged mode
        read_reg(3'h0, rd);
        $display("Unprivileged read security_config_reg = 0x%08x (should be masked/denied)", rd);
        read_reg(3'h1, rd);
        $display("Unprivileged read crypto_key_reg      = 0x%08x (should be masked/denied)", rd);
        read_reg(3'h2, rd);
        $display("Unprivileged read status_reg          = 0x%08x", rd);
        read_reg(3'h3, rd);
        $display("Unprivileged read version_reg         = 0x%08x (should be read-only, not writable)", rd);

        // 3) Attempt privilege escalation via register writes
        // (Assume some future design maps privilege to status_reg or security_config_reg)
        write_reg(3'h2, 32'hFFFF_FFFF); // try to encode higher privilege
        // Check that cpu_privilege_level did NOT change (should be hardware-only)
        @(negedge clk);
        $display("Privilege level after attempted escalation = %0d (should remain 0)", cpu_privilege_level);
    end
    endtask

    // -------------------------
    // CWE-1256: improper restriction of software interfaces to hardware features
    // -------------------------
    task test_cwe1256;
        reg [31:0] rd;
    begin
        $display("=== CWE-1256 test: software access to hardware-only features ===");

        // Assume crypto_key_reg and security_config_reg represent hardware-only controls
        cpu_privilege_level <= 2'b00; // unprivileged
        user_mode           <= 1'b1;

        // 1) Try to manipulate hardware-only features via software-accessible CSRs
        write_reg(3'h1, 32'hDEAD_FACE); // attempt to change hardware key
        write_reg(3'h0, 32'h0BAD_C0DE); // attempt to change security configuration

        // 2) Read back to see if software writes had effect
        read_reg(3'h1, rd);
        $display("Hardware key (crypto_key_reg) after SW write = 0x%08x (should be unaffected)", rd);
        read_reg(3'h0, rd);
        $display("Security config after SW write               = 0x%08x (should be unaffected)", rd);

        // 3) Check direct outputs (hardware view)
        $display("crypto_key output      = 0x%08x (should not be SW-controlled)", crypto_key);
        $display("security_config output = 0x%08x (should not be SW-controlled)", security_config);
    end
    endtask

    // -------------------------
    // Test sequence
    // -------------------------
    initial begin
        // Initialize inputs
        rst_n              = 1'b0;
        reg_wen            = 1'b0;
        reg_ren            = 1'b0;
        reg_addr           = 3'b000;
        reg_wdata          = 32'h0;
        cpu_privilege_level= 2'b00;
        user_mode          = 1'b1;

        // Bring DUT out of reset
        @(negedge clk);
        rst_n <= 1'b1;

        // Run CWE-specific tests
        test_cwe226;
        test_cwe1262;
        test_cwe1256;

        $display("=== Testbench completed ===");
        $finish;
    end

endmodule
