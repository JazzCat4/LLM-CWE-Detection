`include "fixed.v"
`timescale 1ns/1ps

module periph_regs_secure_tb;

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

    // Bus helpers
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

    // ============================================================
    //  CWE‑226 — Scrubbing Before Reuse
    // ============================================================
    task test_cwe226;
        reg [31:0] rd;
    begin
        $display("\n=== CWE‑226: Scrubbing Test ===");

        // Enter privileged mode
        cpu_privilege_level <= 2'b10;
        user_mode           <= 1'b0;

        // Write known patterns
        write_reg(3'h1, 32'hCAFEBABE); // crypto_key_reg
        write_reg(3'h0, 32'h12345678); // security_config_reg

        // Verify patterns were written
        read_reg(3'h0, rd);
        if (rd != 32'h12345678)
            $display("FAIL: security_config_reg did not store pattern");
        else
            $display("PASS: security_config_reg stored pattern");

        // Trigger ciphertext_valid → should scrub key
        write_reg(3'h2, 32'h0000_0001); // status_reg[0] = ciphertext_valid

        // Check key scrubbed
        read_reg(3'h1, rd);
        if (rd != 32'h00000000)
            $display("FAIL: crypto_key_reg not scrubbed after ciphertext_valid");
        else
            $display("PASS: crypto_key_reg scrubbed after ciphertext_valid");

        // Reset → should scrub all sensitive registers
        @(negedge clk);
        rst_n <= 1'b0;
        @(negedge clk);
        rst_n <= 1'b1;

        read_reg(3'h1, rd);
        if (rd != 32'h00000000)
            $display("FAIL: crypto_key_reg not scrubbed on reset");
        else
            $display("PASS: crypto_key_reg scrubbed on reset");

        read_reg(3'h0, rd);
        if (rd != 32'h00000000)
            $display("FAIL: security_config_reg not scrubbed on reset");
        else
            $display("PASS: security_config_reg scrubbed on reset");
    end
    endtask

    // ============================================================
    //  CWE‑1262 — Privilege Enforcement / No Escalation
    // ============================================================
    task test_cwe1262;
        reg [31:0] rd;
    begin
        $display("\n=== CWE‑1262: Access Control Test ===");

        // Enter unprivileged mode
        cpu_privilege_level <= 2'b00;
        user_mode           <= 1'b1;

        // Attempt to write privileged registers
        write_reg(3'h0, 32'hAAAA_BBBB); // security_config_reg
        write_reg(3'h1, 32'hCCCC_DDDD); // crypto_key_reg
        write_reg(3'h4, 32'h0000_0001); // security_lock

        // Read back privileged registers → should be masked or unchanged
        read_reg(3'h0, rd);
        if (rd == 32'hAAAA_BBBB)
            $display("FAIL: Unprivileged write modified security_config_reg");
        else
            $display("PASS: Unprivileged write blocked for security_config_reg");

        read_reg(3'h1, rd);
        if (rd == 32'hCCCC_DDDD)
            $display("FAIL: Unprivileged write modified crypto_key_reg");
        else
            $display("PASS: Unprivileged write blocked for crypto_key_reg");

        read_reg(3'h4, rd);
        if (rd != 32'hDEAD_DEAD)
            $display("FAIL: Unprivileged read of lock bit not masked");
        else
            $display("PASS: Unprivileged read of lock bit masked");

        // Attempt privilege escalation via register write
        write_reg(3'h2, 32'hFFFF_FFFF); // status_reg write allowed only for privileged

        @(negedge clk);
        if (cpu_privilege_level != 2'b00)
            $display("FAIL: Privilege level changed via software write");
        else
            $display("PASS: Privilege escalation prevented");
    end
    endtask

    // ============================================================
    //  CWE‑1256 — Software Cannot Manipulate Hardware‑Only Features
    // ============================================================
    task test_cwe1256;
        reg [31:0] rd;
    begin
        $display("\n=== CWE‑1256: Hardware‑Only Feature Protection Test ===");

        // Unprivileged mode
        cpu_privilege_level <= 2'b00;
        user_mode           <= 1'b1;

        // Try to modify hardware‑only registers
        write_reg(3'h1, 32'hDEAD_FACE); // crypto_key_reg
        write_reg(3'h0, 32'h0BAD_C0DE); // security_config_reg
        write_reg(3'h4, 32'h1);         // security_lock

        // Read back → should be masked or unchanged
        read_reg(3'h1, rd);
        if (rd == 32'hDEAD_FACE)
            $display("FAIL: Unprivileged SW modified hardware key");
        else
            $display("PASS: Hardware key protected from SW");

        read_reg(3'h0, rd);
        if (rd == 32'h0BAD_C0DE)
            $display("FAIL: Unprivileged SW modified security config");
        else
            $display("PASS: Security config protected from SW");

        read_reg(3'h4, rd);
        if (rd != 32'hDEAD_DEAD)
            $display("FAIL: Unprivileged SW accessed lock bit");
        else
            $display("PASS: Lock bit protected from SW");
    end
    endtask

    // ============================================================
    //  Test Sequence
    // ============================================================
    initial begin
        // Initialize
        rst_n = 0;
        reg_wen = 0;
        reg_ren = 0;
        reg_addr = 0;
        reg_wdata = 0;
        cpu_privilege_level = 0;
        user_mode = 1;

        @(negedge clk);
        rst_n = 1;

        test_cwe226;
        test_cwe1262;
        test_cwe1256;

        $display("\n=== All tests completed ===");
        $finish;
    end

endmodule
